/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// The payer's half of free credits (SPEC.md § 3a "Free credits"): fetching
// them from the issuers a host names, keeping them until a free Solana reserve
// carries one, and choosing which reserve does. The TS twin is
// sdk/src/solana/credits.ts.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/TxnLab/zerosignal/go/freecredit"
	"github.com/TxnLab/zerosignal/go/ticket"
)

const (
	// DefaultFreeCreditBatch is how many credits one fetch asks an issuer for.
	// More than one, so a node's next free turns need no fetch and an issuer
	// can't time each fetch against the turn that follows it; few, so a node
	// that goes down that day wastes little.
	DefaultFreeCreditBatch = 3
	// freeCreditFetchTimeout bounds one fetch, the day key and the signatures
	// together. The turn waits on it, and goes without a credit past it.
	freeCreditFetchTimeout = 5 * time.Second
	// freeCreditFailureBackoff is how long an issuer that failed is skipped,
	// so a down issuer costs one timeout a minute rather than one a turn.
	freeCreditFailureBackoff = time.Minute
	// freeCreditMaxBody caps an issuer's answer: twenty 4096-bit signatures in
	// base64 are under 15 KiB.
	freeCreditMaxBody = 1 << 20
)

// FreeCredits configures free credits: an issuer's blind signature that a free
// Solana reserve carries, which lets a node that trusts the issuer tell this
// payer's free turn from a sybil's. With no Issuers a payer fetches none and
// is served on each node's own free budget, as before.
type FreeCredits struct {
	// Issuers maps an issuer's key, standard base64 of its Ed25519 public key
	// as cluster presets and node details spell it, to how to reach it. A
	// reserve carries a credit only from an issuer here that the node
	// advertises trusting.
	Issuers map[string]CreditIssuer
	// Store keeps credits fetched and not yet spent. Nil keeps them in
	// memory, so a restart fetches anew.
	Store CreditStore
	// Batch is how many credits one fetch asks for (DefaultFreeCreditBatch),
	// at most freecredit.MaxIssueBatch.
	Batch int
}

func (f FreeCredits) validate() error {
	if f.Batch > freecredit.MaxIssueBatch {
		return configError(fmt.Sprintf("FreeCredits.Batch %d is above %d", f.Batch, freecredit.MaxIssueBatch))
	}
	for k, port := range f.Issuers {
		if _, err := freecredit.ParseIssuerKey(k); err != nil {
			return configError(fmt.Sprintf("FreeCredits.Issuers: %v", err))
		}
		if port == nil {
			return configError(fmt.Sprintf("FreeCredits.Issuers[%q] is nil", k))
		}
	}
	return nil
}

// CreditIssuer is one issuer's side of the issue wire (freecredit.DayKeyPath,
// freecredit.IssuePath). HTTPCreditIssuer speaks it over HTTP.
type CreditIssuer interface {
	// DayKey is the issuer's certified day key for dep and epoch.
	DayKey(ctx context.Context, dep ticket.DeploymentID, epoch freecredit.Epoch) (freecredit.DayKeyCert, error)
	// Issue returns the issuer's blind signatures over blinded, in order. It
	// may return fewer than asked: the first len of them.
	Issue(ctx context.Context, dep ticket.DeploymentID, epoch freecredit.Epoch, blinded [][]byte) ([][]byte, error)
}

// CreditsExhaustedError is an issuer's 429 credits_exhausted: the caller's
// credits for the day are spent until RetryAfter, zero when it gave none.
type CreditsExhaustedError struct {
	RetryAfter time.Duration
}

func (e *CreditsExhaustedError) Error() string {
	return fmt.Sprintf("free credit issuer: %s (retry after %s)", freecredit.CodeCreditsExhausted, e.RetryAfter)
}

// HTTPCreditIssuer is a CreditIssuer over the issue wire at URL.
type HTTPCreditIssuer struct {
	// URL is the issuer's base URL, the paths appended to it.
	URL string
	// Client sends the requests; nil uses http.DefaultClient.
	Client *http.Client
	// Header adds what the issuer's gate asks of a caller, such as proof of a
	// check it passed, to each request's headers. Nil adds nothing.
	Header func(ctx context.Context, h http.Header) error
}

func (h *HTTPCreditIssuer) DayKey(ctx context.Context, dep ticket.DeploymentID, epoch freecredit.Epoch) (freecredit.DayKeyCert, error) {
	var cert freecredit.DayKeyCert
	err := h.post(ctx, freecredit.DayKeyPath, freecredit.DayKeyRequest{Deployment: dep[:], Epoch: epoch}, &cert)
	return cert, err
}

func (h *HTTPCreditIssuer) Issue(ctx context.Context, dep ticket.DeploymentID, epoch freecredit.Epoch, blinded [][]byte) ([][]byte, error) {
	req := freecredit.IssueRequest{Deployment: dep[:], Epoch: epoch, Blinded: make([]freecredit.Bytes, len(blinded))}
	for i, b := range blinded {
		req.Blinded[i] = b
	}
	var resp freecredit.IssueResponse
	if err := h.post(ctx, freecredit.IssuePath, req, &resp); err != nil {
		return nil, err
	}
	out := make([][]byte, len(resp.Signatures))
	for i, s := range resp.Signatures {
		out[i] = s
	}
	return out, nil
}

func (h *HTTPCreditIssuer) post(ctx context.Context, path string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(h.URL, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("free credit issuer: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if h.Header != nil {
		if err := h.Header(ctx, req.Header); err != nil {
			return fmt.Errorf("free credit issuer: %w", err)
		}
	}
	client := h.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("free credit issuer: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, freeCreditMaxBody))
	if err != nil {
		return fmt.Errorf("free credit issuer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		code := openAIErrorCode(data)
		if resp.StatusCode == http.StatusTooManyRequests && code == freecredit.CodeCreditsExhausted {
			return &CreditsExhaustedError{RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
		}
		return fmt.Errorf("free credit issuer: %s answered %d %s", path, resp.StatusCode, code)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("free credit issuer: %s: %w", path, err)
	}
	return nil
}

// CreditKey names the credits a store keeps together: one issuer's, for one
// node, on one day.
type CreditKey struct {
	Deployment ticket.DeploymentID
	Node       freecredit.Node
	Epoch      freecredit.Epoch
	// Issuer is the issuer's key as FreeCredits.Issuers spells it.
	Issuer string
}

// CreditStore keeps credits fetched and not yet spent. A lost credit costs
// only its payer a fetch, so a store need not be durable. One that outlives
// the process saves a reload its fetches, and the payer's turns their timing.
type CreditStore interface {
	// Take removes one credit kept under key and returns it, or false.
	Take(ctx context.Context, key CreditKey) (freecredit.Credit, bool, error)
	// Put keeps credits under key.
	Put(ctx context.Context, key CreditKey, credits []freecredit.Credit) error
}

// NewMemoryCreditStore is a CreditStore in memory. It forgets each day's
// credits once a later day's are put.
func NewMemoryCreditStore() CreditStore {
	return &memoryCreditStore{credits: map[CreditKey][]freecredit.Credit{}}
}

type memoryCreditStore struct {
	mu      sync.Mutex
	credits map[CreditKey][]freecredit.Credit
}

func (m *memoryCreditStore) Take(_ context.Context, key CreditKey) (freecredit.Credit, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cs := m.credits[key]
	if len(cs) == 0 {
		return freecredit.Credit{}, false, nil
	}
	c := cs[len(cs)-1]
	if len(cs) == 1 {
		delete(m.credits, key)
	} else {
		m.credits[key] = cs[:len(cs)-1]
	}
	return c, true, nil
}

func (m *memoryCreditStore) Put(_ context.Context, key CreditKey, credits []freecredit.Credit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// A node accepts yesterday's credits only in the grace after midnight,
	// so anything older is dead weight.
	for k := range m.credits {
		if k.Epoch+1 < key.Epoch {
			delete(m.credits, k)
		}
	}
	m.credits[key] = append(m.credits[key], credits...)
	return nil
}

// creditWallet fetches credits on demand, a node at a time, and holds them
// until a reserve carries one.
type creditWallet struct {
	dep     ticket.DeploymentID
	issuers map[string]*creditIssuer
	store   CreditStore
	batch   int
	clock   func() time.Time
	log     *slog.Logger
	// random feeds the blinding; nil is crypto/rand.
	random io.Reader
	// fetchTimeout is freeCreditFetchTimeout, shorter in tests.
	fetchTimeout time.Duration

	mu      sync.Mutex
	flights map[CreditKey]chan struct{}
	// refused is the day each node last refused a credit on. It is sent none
	// for the rest of that day: a node that won't take this payer's credits,
	// with a clock past the grace or an issuer it no longer trusts, or that
	// answers refusals to burn them, costs one or two credits a day, not a
	// batch a turn.
	refused map[freecredit.Node]freecredit.Epoch
}

type creditIssuer struct {
	key  ed25519.PublicKey
	port CreditIssuer
	// Guarded by the wallet's mu.
	skipUntil time.Time
	// dayKeys is the verified day key per epoch. A payer blinds every credit
	// of a day to the one key it fetched first, so the issuer can't tell its
	// fetches apart by key.
	dayKeys map[freecredit.Epoch]*freecredit.DayKey
}

// newCreditWallet builds the wallet for cfg on the deployment dep names, or
// nil when cfg names no issuer, the rail is not Solana, or the id is unknown:
// a credit is minted for one deployment. Keys and batch were checked by
// Config.validate.
func newCreditWallet(cfg FreeCredits, rail ticket.Rail, dep ticket.DeploymentID, clock func() time.Time, log *slog.Logger) *creditWallet {
	if len(cfg.Issuers) == 0 || rail != ticket.RailSolana || dep.IsZero() {
		return nil
	}
	w := &creditWallet{
		dep: dep, issuers: map[string]*creditIssuer{}, store: cfg.Store,
		batch: cfg.Batch, clock: clock, log: log, fetchTimeout: freeCreditFetchTimeout,
		flights: map[CreditKey]chan struct{}{}, refused: map[freecredit.Node]freecredit.Epoch{},
	}
	if w.store == nil {
		w.store = NewMemoryCreditStore()
	}
	if w.batch == 0 {
		w.batch = DefaultFreeCreditBatch
	}
	for k, port := range cfg.Issuers {
		pub, err := freecredit.ParseIssuerKey(k)
		if err != nil || port == nil {
			continue
		}
		w.issuers[k] = &creditIssuer{key: pub, port: port, dayKeys: map[freecredit.Epoch]*freecredit.DayKey{}}
	}
	return w
}

// creditIssuersFor is the issuers a reserve for model at op may carry a
// credit from: the ones the node advertises, on Solana, for a model it prices
// at nothing. Anything priced, an image route or a priced tool included, is a
// paid reserve, whose ticket opens on chain and needs no credit. The TS twin
// is creditIssuersFor in sdk/src/solana/credits.ts, pinned by
// testdata/operator_vectors.json.
func creditIssuersFor(rail ticket.Rail, op Operator, model string) []string {
	if rail != ticket.RailSolana || len(op.FreeCreditIssuers) == 0 {
		return nil
	}
	c, ok := op.ModelCapacities[model]
	if !ok || !c.pricesNothing() {
		return nil
	}
	return op.FreeCreditIssuers
}

// pricesNothing reports whether every rate the node advertises for the model
// is zero.
func (c ModelCapacity) pricesNothing() bool {
	zero := func(p *float64) bool { return p == nil || *p == 0 }
	return c.InputUSDPer1M == 0 && c.OutputUSDPer1M == 0 && zero(c.CacheReadUSDPer1M) &&
		zero(c.LongContextInputUSDPer1M) && zero(c.LongContextOutputUSDPer1M) && zero(c.LongContextCacheReadUSDPer1M) &&
		!c.ServesImageGen() && !c.ServesImageEdit() &&
		c.ImageToolRateMicroUSDC == 0 && c.ImageEditToolRateMicroUSDC == 0 &&
		c.MaxZsToolRateMicroUSDC() == 0 && c.MaxVendorToolRateMicroUSDC() == 0
}

// reserveCodeIs reports whether a reserve failed with the node's code.
func reserveCodeIs(err error, code string) bool {
	re, ok := AsReserveHTTP(err)
	return ok && re.Code == code
}

// creditRefused reports whether a reserve failed on the credit it carried.
func creditRefused(err error) bool {
	return reserveCodeIs(err, freecredit.CodeFreeCreditInvalid) || reserveCodeIs(err, freecredit.CodeFreeCreditSpent)
}

// heldCredit is a credit a reserve carries. It goes back to the store unless
// the turn reached the node or the node refused the credit itself.
type heldCredit struct {
	w      *creditWallet
	key    CreditKey
	credit freecredit.Credit
	raw    json.RawMessage
	done   bool
}

// spend marks the credit used: the sealed turn is on its way to the node,
// which consumes it.
func (h *heldCredit) spend() {
	if h != nil {
		h.done = true
	}
}

// drop discards a credit the node refused.
func (h *heldCredit) drop() { h.spend() }

// giveBack returns an unused credit to the store, for the node's next turn.
func (h *heldCredit) giveBack(ctx context.Context) {
	if h == nil || h.done {
		return
	}
	h.done = true
	// Past the caller's cancel, so a credit isn't lost to it, but bounded, so
	// a stuck host store can't hold the turn.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), h.w.fetchTimeout)
	defer cancel()
	if err := h.w.store.Put(ctx, h.key, []freecredit.Credit{h.credit}); err != nil {
		h.w.log.Warn("free credit could not be kept for the next turn", slog.Any("err", err))
	}
}

// refuse sends node no credit for the rest of today.
func (w *creditWallet) refuse(node freecredit.Node) {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.refused[node] = freecredit.EpochAt(w.clock())
	w.mu.Unlock()
}

// take returns a credit for node from the first of issuers that has one, kept
// or fetched now, or nil. Nil is never an error: the reserve goes out without
// a credit and the node serves it on its own budget.
func (w *creditWallet) take(ctx context.Context, issuers []string, node freecredit.Node) *heldCredit {
	if w == nil || len(issuers) == 0 {
		return nil
	}
	epoch := freecredit.EpochAt(w.clock())
	w.mu.Lock()
	refused, ok := w.refused[node]
	w.mu.Unlock()
	if ok && refused == epoch {
		return nil
	}
	for _, k := range issuers {
		is := w.issuers[k]
		if is == nil {
			continue
		}
		key := CreditKey{Deployment: w.dep, Node: node, Epoch: epoch, Issuer: k}
		if h := w.stored(ctx, key); h != nil {
			return h
		}
		if h := w.fetch(ctx, is, key); h != nil {
			return h
		}
	}
	return nil
}

func (w *creditWallet) stored(ctx context.Context, key CreditKey) *heldCredit {
	c, ok, err := w.store.Take(ctx, key)
	if err != nil {
		w.log.Warn("free credit store could not be read", slog.Any("err", err))
		return nil
	}
	if !ok {
		return nil
	}
	return w.hold(key, c)
}

func (w *creditWallet) hold(key CreditKey, c freecredit.Credit) *heldCredit {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	return &heldCredit{w: w, key: key, credit: c, raw: raw}
}

// fetch mints a batch for key, one fetch per key at a time: a turn that finds
// one running waits for it and takes from what it kept.
func (w *creditWallet) fetch(ctx context.Context, is *creditIssuer, key CreditKey) *heldCredit {
	w.mu.Lock()
	if w.clock().Before(is.skipUntil) {
		w.mu.Unlock()
		return nil
	}
	if running, ok := w.flights[key]; ok {
		w.mu.Unlock()
		select {
		case <-running:
		case <-ctx.Done():
			return nil
		}
		return w.stored(ctx, key)
	}
	done := make(chan struct{})
	w.flights[key] = done
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		delete(w.flights, key)
		w.mu.Unlock()
		close(done)
	}()

	credits, err := w.mint(ctx, is, key)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		w.skip(is, err)
		return nil
	}
	if len(credits) > 1 {
		if err := w.store.Put(ctx, key, credits[1:]); err != nil {
			w.log.Warn("free credits could not be kept for later turns", slog.Any("err", err))
		}
	}
	return w.hold(key, credits[0])
}

// skip benches is after err: until the issuer's Retry-After once its cap is
// spent, else freeCreditFailureBackoff.
func (w *creditWallet) skip(is *creditIssuer, err error) {
	now := w.clock()
	wait := freeCreditFailureBackoff
	if ce := (*CreditsExhaustedError)(nil); errors.As(err, &ce) {
		// The cap counts per day, so with no hint it holds until the next.
		wait = (freecredit.EpochAt(now) + 1).Start().Sub(now)
		if ce.RetryAfter > 0 {
			wait = min(ce.RetryAfter, 24*time.Hour)
		}
		wait = max(wait, freeCreditFailureBackoff)
	}
	w.mu.Lock()
	is.skipUntil = now.Add(wait)
	w.mu.Unlock()
	w.log.Info("free credit issuer skipped; turns go without its credits meanwhile",
		slog.Duration("for", wait), slog.Any("err", err))
}

// mint fetches and finalizes one batch of credits for key.
func (w *creditWallet) mint(ctx context.Context, is *creditIssuer, key CreditKey) ([]freecredit.Credit, error) {
	ctx, cancel := context.WithTimeout(ctx, w.fetchTimeout)
	defer cancel()
	dk, err := w.dayKey(ctx, is, key.Epoch)
	if err != nil {
		return nil, err
	}
	blinded := make([][]byte, w.batch)
	pending := make([]*freecredit.Pending, w.batch)
	for i := range blinded {
		if blinded[i], pending[i], err = freecredit.Blind(w.random, dk, w.dep, key.Node); err != nil {
			return nil, err
		}
	}
	sigs, err := is.port.Issue(ctx, w.dep, key.Epoch, blinded)
	if err != nil {
		return nil, err
	}
	if len(sigs) > len(blinded) {
		return nil, fmt.Errorf("free credit issuer: %d signatures for %d messages", len(sigs), len(blinded))
	}
	var out []freecredit.Credit
	for i, s := range sigs {
		// Finalize verifies, so a signature under another key is never kept.
		c, err := pending[i].Finalize(s)
		if err != nil {
			return nil, fmt.Errorf("free credit issuer: signature %d: %w", i, err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("free credit issuer: signed none")
	}
	return out, nil
}

// dayKey is is's verified day key for epoch, fetched once.
func (w *creditWallet) dayKey(ctx context.Context, is *creditIssuer, epoch freecredit.Epoch) (*freecredit.DayKey, error) {
	w.mu.Lock()
	dk := is.dayKeys[epoch]
	w.mu.Unlock()
	if dk != nil {
		return dk, nil
	}
	cert, err := is.port.DayKey(ctx, w.dep, epoch)
	if err != nil {
		return nil, err
	}
	if cert.Epoch != epoch {
		return nil, fmt.Errorf("free credit issuer: day key for epoch %d, asked for %d", cert.Epoch, epoch)
	}
	if dk, err = freecredit.VerifyDayKey([]ed25519.PublicKey{is.key}, w.dep, cert); err != nil {
		return nil, fmt.Errorf("free credit issuer: day key: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if kept := is.dayKeys[epoch]; kept != nil {
		// A concurrent fetch for another node got there first; keep one key.
		return kept, nil
	}
	for e := range is.dayKeys {
		if e+1 < epoch {
			delete(is.dayKeys, e)
		}
	}
	is.dayKeys[epoch] = dk
	return dk, nil
}
