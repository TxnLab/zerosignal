/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/transient"
	"github.com/TxnLab/zerosignal/go/wire"
)

// ReservedTicket bundles everything a reserve call hands back. The
// ticket is the wire object the proxy forwards around; ResponseKey is
// K_response unwrapped from the node's WrappedResponseKey (needed to
// compute the admission tag on the next request and also to decrypt
// that request's response); AgeIdentity is the ephemeral age identity
// the proxy declared as proxy_recipient — it's the private half of
// what K_response was wrapped to, and it's reused as the envelope's
// reply_to_recipient so the same identity can unwrap both the reserve-
// time K_response and the response-time X-Zs-Response-Key.
//
// AlgoUSDPrice is the ALGO/USD rate the node observed at reserve time.
// It is NOT used to derive the ticket's pricing (those are microUSDC,
// converted directly from USD with no oracle in the path); the proxy
// uses it to surface ALGO network-fee dollar amounts in logs and on
// the wire without querying the oracle itself. Zero on older nodes
// that don't return it.
type ReservedTicket struct {
	Ticket       *ticket.Ticket
	ResponseKey  [wire.ResponseKeySize]byte
	AgeIdentity  *age.X25519Identity
	AlgoUSDPrice float64

	// SealRecipient is the age recipient this reserve's body was actually
	// sealed to — the operator's verified, unexpired ephemeral recipient
	// (mandatory forward secrecy; there is no anchor). Dispatch MUST seal the
	// follow-up inference request to this exact recipient (dispatch.go
	// WrapRequestWithIdentity) rather than re-deriving from the operator
	// record: a mid-flight registry refresh could rotate the operator's
	// ephemeral between reserve and inference, and the node only guarantees
	// it can still decrypt what reserve committed to. Pinning keeps reserve
	// and inference on one recipient. Never nil on a successful Reserve.
	SealRecipient age.Recipient

	// PreSignedOpenGroup is the operator-pre-signed 2-tx open group
	// the proxy completes via SubmitPresignedOpenGroup at open time.
	// gtxn[1] (the operator's open() AppCall) is signed; gtxn[0]
	// (the payer-signed usdcPayment) carries an empty Sig and is
	// signed by the wallet at submit. The per-ticket box MBR is no
	// longer a funding leg here — it's drawn from the payer's prepaid
	// MBR pool at open(). Empty when the operator's node is running
	// ticket-only admission (no on-chain escrow).
	PreSignedOpenGroup []types.SignedTxn
}

// Wipe zeroes ResponseKey and AgeIdentity, best effort. SPEC § 3: the payer
// keeps no per-request ephemeral material past the response handler. Call it
// once the response is read, or when the ticket is dropped unopened. Safe on
// nil.
func (rt *ReservedTicket) Wipe() {
	if rt == nil {
		return
	}
	clear(rt.ResponseKey[:])
	wire.ZeroEphemeralIdentity(rt.AgeIdentity)
}

// BusyError is returned from ReserveClient.Reserve when an operator
// replies with HTTP 429. RetryAfter is the value the operator hinted,
// clamped to a sane range; zero means no hint was provided.
//
// Code is the node's OpenAI-shaped `error.code`, empty when the body carried
// none. It is load-bearing, not diagnostic: a 429 is four conditions and only
// one of them may be re-asked. Which one, and why re-asking the others is
// harmful, is transient.RetryableBusyCode's to say — the node emits the codes
// from the same package.
type BusyError struct {
	RetryAfter time.Duration
	Code       string
}

// Retryable reports whether re-asking this operator can produce a different
// answer within a few seconds.
func (e *BusyError) Retryable() bool { return e != nil && transient.RetryableBusyCode(e.Code) }

func (e *BusyError) Error() string {
	if e.RetryAfter == 0 {
		return "operator busy (no retry-after hint)"
	}
	return fmt.Sprintf("operator busy (retry after %s)", e.RetryAfter)
}

// IsBusy reports whether err is a *BusyError (directly or wrapped).
func IsBusy(err error) bool {
	var be *BusyError
	return errors.As(err, &be)
}

// ReserveHTTPError is returned from ReserveClient.Reserve for a failure the
// client has no more specific type for: any non-200 that isn't a 429 / sizing
// 400 / payer refusal / signature skew, plus a transport failure that never
// produced a response at all.
//
// It exists so the dispatch loop can run the shared transient.Classify over the
// raw facts instead of pattern-matching a formatted string. The distinction it
// unlocks is the one that matters operationally: a 502/503/504 carrying no
// protocol error code is an operator's CDN / ingress / LB having a moment (most
// often while the node restarts), which clears on its own within seconds — while
// the same status carrying a node code is a considered refusal. Before this
// type both collapsed into one opaque error and the caller could only give up on
// that operator.
//
// Status is transient.TransportFailureStatus (0) when no response arrived; Err
// then holds the underlying transport error and is exposed via Unwrap.
type ReserveHTTPError struct {
	Status     int           // HTTP status, or 0 for a transport failure
	Code       string        // OpenAI-shaped error.code; empty for an HTML / empty / unparseable body
	RetryAfter time.Duration // server hint, zero when absent
	Message    string        // truncated body or transport error text — logs only, never surfaced verbatim
	Err        error         // underlying transport error; nil when an HTTP response arrived

	// RelayHopMarked reports whether the response carried wire.RelayHopHeader,
	// i.e. the relay's own handler produced or forwarded it. Meaningful only on
	// a relayed request, and always false on a transport failure (no response
	// arrived to carry it).
	//
	// Kept as one extracted bit rather than the raw http.Header, matching how
	// Status / Code / RetryAfter are already extracted facts: this type's
	// contract is "the raw inputs a classifier needs", and handing callers a
	// whole header set invites reading things that have no business crossing
	// this seam. Consumed via transient.NarrowRelayed — see classifyReserveErr.
	RelayHopMarked bool
}

func (e *ReserveHTTPError) Error() string {
	if e.Status == 0 {
		return fmt.Sprintf("reserve: %s", e.Message)
	}
	return fmt.Sprintf("reserve: HTTP %d: %s", e.Status, e.Message)
}

func (e *ReserveHTTPError) Unwrap() error { return e.Err }

// AsReserveHTTP extracts a *ReserveHTTPError from err (directly or wrapped).
func AsReserveHTTP(err error) (*ReserveHTTPError, bool) {
	var re *ReserveHTTPError
	if errors.As(err, &re) && re != nil {
		return re, true
	}
	return nil, false
}

// SizeError is returned from ReserveClient.Reserve when an operator
// replies with HTTP 400 and an OpenAI-shaped error body whose code
// identifies a sizing/context-window mismatch (today: only
// "context_length_exceeded", emitted by node/internal/server/reserve.go
// when max_output_tokens > the operator's per-model output cap or when
// max_output_tokens >= the model's context window). The dispatch loop
// uses this to distinguish hard client-side request-size errors from
// transient 429s — a sizing failure is not retryable against the same
// operator and should not be folded into "operators_busy".
//
// Code mirrors the node's OpenAI-shaped `error.code`; Message mirrors
// `error.message` so the proxy can surface the underlying reason
// verbatim when every candidate rejects for sizing.
type SizeError struct {
	Code    string
	Message string
}

func (e *SizeError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("operator rejected request: %s", e.Code)
	}
	return fmt.Sprintf("operator rejected request: %s: %s", e.Code, e.Message)
}

// IsSize reports whether err is a *SizeError (directly or wrapped).
func IsSize(err error) bool {
	var se *SizeError
	return errors.As(err, &se)
}

// PayerRefusalError is returned when a node refuses the reserve for a reason
// scoped to the PAYER rather than to the operator — the escrow contract's
// per-payer state says no. Today that means the payer has spent its daily
// allowance of free (max_price 0) tickets.
//
// The distinction matters to the dispatch loop: the cap is enforced ON CHAIN
// against the payer, so every other operator refuses the identical request
// identically. Walking the candidate list burns a reserve round-trip per
// operator and then reports `operators_busy`, telling the caller the network is
// congested and inviting a retry storm against a condition that can take a full
// day to clear. So this is terminal: stop iterating and surface it.
//
// `payer_not_opted_in` (the payer holds no prepaid-pool opt-in in the escrow
// app, SPEC § 3a "Funds gate") is
// the same shape: every node reads the same account, and each refusal costs
// the payer a strike on that node.
type PayerRefusalError struct {
	Code       string
	Message    string
	RetryAfter time.Duration
}

func (e *PayerRefusalError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("operator refused for a payer-scoped reason: %s", e.Code)
	}
	return fmt.Sprintf("operator refused for a payer-scoped reason: %s: %s", e.Code, e.Message)
}

// AsPayerRefusal extracts a *PayerRefusalError from err (directly or wrapped).
// Callers that need the code / message / reset should use this rather than
// IsPayerRefusal followed by their own errors.As — the two-step form leaves a
// nil pointer live on the false branch, one refactor away from a panic in the
// dispatch loop.
func AsPayerRefusal(err error) (*PayerRefusalError, bool) {
	var pe *PayerRefusalError
	if errors.As(err, &pe) && pe != nil {
		return pe, true
	}
	return nil, false
}

// IsPayerRefusal reports whether err is a *PayerRefusalError (directly or
// wrapped). Use AsPayerRefusal when you need the value itself.
func IsPayerRefusal(err error) bool {
	_, ok := AsPayerRefusal(err)
	return ok
}

// payerRefusalCodes is the closed set of OpenAI-shaped error codes the proxy
// treats as a payer-scoped, every-operator-agrees refusal. Kept as a small
// allowlist for the same reason as sizingErrorCodes: adding a code changes
// dispatch behavior and should match what the node actually emits.
var payerRefusalCodes = map[string]struct{}{
	"free_quota_exhausted": {},
	"payer_not_opted_in":   {},
}

// parsePayerRefusal decodes an OpenAI-shaped error body and returns a
// *PayerRefusalError when the code is one of the recognized payer-scoped
// refusals. Returns nil otherwise so callers fall back to the generic path.
func parsePayerRefusal(body []byte, retryAfter time.Duration) *PayerRefusalError {
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil
	}
	if _, ok := payerRefusalCodes[env.Error.Code]; !ok {
		return nil
	}
	return &PayerRefusalError{Code: env.Error.Code, Message: env.Error.Message, RetryAfter: retryAfter}
}

// payerSigSkewError is returned by reserveAttempt when the node rejected the
// reserve payer signature with 401 invalid_payer_sig and embedded its own
// clock as node_time — the signal that our payer_issued_at fell outside the
// signature window (clock skew or a slow round-trip). Reserve re-stamps
// payer_issued_at to nodeTime, re-signs, and retries once. It is only produced
// when the 401 carried a parseable node_time; otherwise reserveAttempt returns
// the generic non-200 error and no resync is attempted.
type payerSigSkewError struct {
	nodeTime int64
	// http is the 401 as any other refusal, which Reserve returns when it
	// can't resync: the dispatcher classifies a *ReserveHTTPError, and this
	// type would otherwise reach it as an unknown error and read as busy.
	http *ReserveHTTPError
}

func (e *payerSigSkewError) Error() string {
	return fmt.Sprintf("reserve: payer signature rejected (node_time=%d)", e.nodeTime)
}

// parseNodeTime extracts the node_time=<unix seconds> hint the node stamps into
// a 401 invalid_payer_sig message. Returns (0, false) when absent/unparseable.
func parseNodeTime(msg string) (int64, bool) {
	const marker = "node_time="
	i := strings.Index(msg, marker)
	if i < 0 {
		return 0, false
	}
	rest := msg[i+len(marker):]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j == 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(rest[:j], 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// sizingErrorCodes is the closed set of OpenAI-shaped error codes that
// the proxy treats as a hard sizing rejection from a node's reserve
// handler. Kept as a small allowlist — adding a code here is a wire-
// behavior change that should match what the node actually emits.
var sizingErrorCodes = map[string]struct{}{
	"context_length_exceeded": {},
}

// parseSizeError decodes an OpenAI-shaped error body and returns a
// *SizeError when the code is one of the recognized sizing rejections.
// Returns nil when the body is malformed or the code is something else;
// callers fall back to the generic non-200 error path.
func parseSizeError(body []byte) *SizeError {
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil
	}
	if _, ok := sizingErrorCodes[env.Error.Code]; !ok {
		return nil
	}
	return &SizeError{Code: env.Error.Code, Message: env.Error.Message}
}

// ReserveClient issues POST /v1/zs/reserve against a specific
// operator. It verifies the returned ticket's signature and basic shape
// so callers can rely on the ticket being genuine before any payment
// work happens. It also unwraps K_response from the response so the
// caller can compute admission tags and decrypt the eventual sealed
// response.
type ReserveClient interface {
	// Reserve posts the reserve request to op. When hop is non-nil the request
	// is routed through that relay (transport-privacy mode); a nil hop sends
	// directly to op.BaseURL. The body is sealed ONLY to the operator's
	// verified, unexpired ephemeral recipient (mandatory forward secrecy — no
	// anchor fallback, no retry-to-anchor); an operator lacking one yields
	// errNoEphemeral instead of a reserve, which the dispatcher treats as
	// "skip this candidate".
	Reserve(ctx context.Context, op Operator, req ticket.ReserveRequest, hop *RelayHop) (*ReservedTicket, error)
}

// HTTPReserveClient is the default ReserveClient — wraps an
// *http.Client. A nil HTTPClient gets the client New would build from a zero
// Config: DefaultReserveTimeout, no environment proxy, and private addresses
// refused at dial. http.DefaultClient is none of those, and a reserve dials a
// node-registered address, which is what the dial guard exists for.
//
// Signer, when non-nil, signs the reserve request under the payer address
// (req.PayerAddr, set by the dispatcher) so the node can authenticate the
// payer instead of trusting the field (SPEC.md §3a "Reserve-request
// signature"). Nil signer ⇒ no payer_sig, which a node accepts under
// verify-if-present — so wiring it is additive and safe to land before the
// node fleet enforces it. The signer is the proxy's keystore
// (keystore.SignBytes satisfies ticket.BytesSigner); the payer key already
// backs the open() group's usdcPayment.
type HTTPReserveClient struct {
	HTTPClient *http.Client
	Signer     ticket.BytesSigner
}

// reservePath is the node-side endpoint from SPEC.md § 3a.
const reservePath = "/v1/zs/reserve"

// defaultReserveHTTPClient is shared so a nil-client HTTPReserveClient still
// reuses connections across reserves.
var defaultReserveHTTPClient = Config{}.nodeHTTPClient(DefaultReserveTimeout, 0)

// DefaultReserveTimeout bounds a single POST /v1/zs/reserve. The
// reserve handler does Algorand simulation in escrow.ComposeOpenGroup
// and signs a ticket — fast on a co-located node, but cross-internet
// operators routinely take a few seconds, so the default sits a step
// above DefaultDetailsFetchTimeout. Operators on slow / distant
// algod nodes may need this raised via zs.reserve_timeout in the
// proxy config; the dispatcher still iterates to the next candidate
// on a timeout, so raising it only delays the failover.
const DefaultReserveTimeout = 5 * time.Second

// badReserveEnvelopeCode is the OpenAI-style error.code the node's
// handleReserve returns (HTTP 400) when it cannot age-open the sealed
// reserve body — i.e. the body was sealed to a recipient whose private
// half the node no longer holds. Under mandatory forward secrecy this can
// only mean a stale ephemeral (the node restarted/rotated since the proxy's
// last registry refresh); there is no durable anchor, so the proxy cannot
// retry — it surfaces the error and the dispatcher moves to the next
// candidate. See node/internal/server/reserve.go.
const badReserveEnvelopeCode = "bad_reserve_envelope"

// errBadReserveEnvelope is the sentinel reserveAttempt returns when the
// node refused the sealed body with badReserveEnvelopeCode — it could not
// age-open the body because the recipient we sealed to is defunct (a
// stale-but-unexpired ephemeral: the node restarted/rotated its in-memory key
// while our cached snapshot's advertised expiry hadn't lapsed yet). Under
// mandatory forward secrecy there is no durable anchor to re-seal to in this
// call, but the dispatcher self-heals — it re-probes the candidate's ephemeral
// live and retries the reserve once (mirroring the errNoEphemeral path) before
// moving on. Reserve preserves (wraps) this sentinel so IsBadReserveEnvelope
// can detect it.
var errBadReserveEnvelope = errors.New("node rejected sealed reserve envelope (bad_reserve_envelope)")

// errNoEphemeral is the sentinel SealRecipient / Reserve return when the
// operator has no valid, unexpired signed ephemeral recipient. Under mandatory
// forward secrecy there is no durable-key fallback, so Reserve refuses to seal
// at all and the dispatcher skips this candidate (it does NOT misclassify as a
// transport error). When every candidate is skipped for this reason the
// dispatcher surfaces 503 no_ephemeral_capacity, mirroring no_tee_capacity. See
// Operator.SealRecipient and proto/SPEC.md § 8.
var errNoEphemeral = errors.New("operator has no valid forward-secrecy ephemeral recipient")

// ErrNoEphemeral exposes the sentinel behind IsNoEphemeral so a caller in
// another package can CONSTRUCT the condition, not just recognise it. The
// dispatcher's stale-ephemeral self-heal (transient_retry.go) is only reachable
// through this error, so testing what that branch does — re-probing and
// re-sizing the reserve against the refreshed operator — requires producing it
// from a stubbed reserve client.
var ErrNoEphemeral = errNoEphemeral

// IsNoEphemeral reports whether err is the no-ephemeral sentinel (directly or
// wrapped). The dispatcher uses it to skip a candidate that lacks a valid
// forward-secrecy ephemeral recipient — distinctly from a generic transport
// error — and to drive the 503 no_ephemeral_capacity terminal response when
// every candidate is skipped for this reason.
func IsNoEphemeral(err error) bool {
	return errors.Is(err, errNoEphemeral)
}

// IsBadReserveEnvelope reports whether err is the bad_reserve_envelope sentinel
// (directly or wrapped). The node could not age-open the sealed reserve body
// because the recipient the proxy sealed to is defunct — a stale-but-unexpired
// ephemeral after a node restart/rotation (distinct from errNoEphemeral, where
// the cached ephemeral has already *expired* and Reserve never contacts the
// node). The dispatcher uses it to re-probe the candidate's ephemeral live and
// retry the reserve once before skipping, the same self-heal it runs for
// IsNoEphemeral; there is no anchor fallback under mandatory forward secrecy.
func IsBadReserveEnvelope(err error) bool {
	return errors.Is(err, errBadReserveEnvelope)
}

// Reserve posts req to op's BaseURL and returns the ticket. Errors fall
// into three buckets:
//
//   - *BusyError: the operator returned 429. Caller should try the next
//     operator (per the affinity policy) or surface 503.
//   - Transport / parse / verification error: the operator is reachable
//     but something went wrong — bad status, malformed JSON, bad ticket
//     signature, commit_k not 32 bytes, etc. Caller typically moves on.
//   - Ticket: success — the returned value has been signature-verified
//     against op.TicketSigningKey.
//
// Recipient selection + mandatory forward secrecy: the sealed body is
// encrypted to op.SealRecipient(now) — the operator's verified, unexpired
// ephemeral recipient. There is no durable-key fallback: if SealRecipient finds
// no valid fresh ephemeral, Reserve returns errNoEphemeral WITHOUT contacting
// the node, and the dispatcher skips the candidate (→ 503 no_ephemeral_capacity
// when every candidate is skipped for this reason). The chosen recipient is
// pinned into the returned ReservedTicket so the follow-up inference seals to
// the same key.
//
// A bad_reserve_envelope (the node can't age-open the body — its ephemeral
// private half is gone after a restart/rotation) is surfaced as the
// errBadReserveEnvelope sentinel (see IsBadReserveEnvelope). There is no anchor
// to re-seal to in this call, but the dispatcher self-heals: it re-probes the
// candidate's ephemeral live and retries the reserve once (mirroring the
// errNoEphemeral path) before moving on.
func (c *HTTPReserveClient) Reserve(ctx context.Context, op Operator, req ticket.ReserveRequest, hop *RelayHop) (*ReservedTicket, error) {
	// Generate the ephemeral age identity up-front: its recipient goes
	// into ProxyRecipient (so the node can wrap K_response back to us),
	// and the same identity is later handed to WrapRequestWithIdentity
	// so the eventual response's X-Zs-Response-Key unwraps cleanly.
	// Callers discard this identity via wire.ZeroEphemeralIdentity
	// once the response is decoded. NOTE this proxy-side reply-to identity
	// is independent of the operator's sealing recipient chosen below.
	ephemeral, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral identity: %w", err)
	}
	// A failed reserve wipes it here; a ticket handed back owns it (Wipe).
	handedBack := false
	defer func() {
		if !handedBack {
			wire.ZeroEphemeralIdentity(ephemeral)
		}
	}()
	req.ProxyRecipient = ephemeral.Recipient().String()

	// Mandatory forward secrecy: seal ONLY to the operator's verified, unexpired
	// ephemeral recipient. Fail fast on no-ephemeral before doing any sign work.
	sealRecipient, err := op.SealRecipient(time.Now())
	if err != nil {
		return nil, err // errNoEphemeral
	}

	// signAndMarshal (optionally) signs the reserve under the payer address —
	// binding the target (op.ID, op.NodeID) and the freshly-generated
	// proxy_recipient as signed context (SPEC.md §3a) — with issuedAt stamped
	// into payer_issued_at, then marshals the body. The signature must precede
	// the marshal (so payer_sig / payer_issued_at ride the sealed body) and the
	// seal (so the signed bytes are exactly what the node opens). No-op when no
	// signer is wired or the request carries no payer (non-escrow / discovery).
	// Called once with the local clock, and again for the one-shot skew resync
	// below with the node's clock.
	signAndMarshal := func(issuedAt int64) ([]byte, error) {
		if c.Signer != nil && req.PayerAddr != "" {
			req.PayerIssuedAt = issuedAt
			if err := req.Sign(ctx, c.Signer, req.PayerAddr, op.ID, op.NodeID); err != nil {
				return nil, fmt.Errorf("sign reserve request: %w", err)
			}
		}
		return json.Marshal(req)
	}

	body, err := signAndMarshal(time.Now().Unix())
	if err != nil {
		return nil, fmt.Errorf("marshal reserve request: %w", err)
	}

	rt, err := c.reserveAttempt(ctx, op, req, body, ephemeral, sealRecipient, hop)
	if err != nil {
		// One-shot clock-skew resync (SPEC.md §3a). The node rejects a
		// present-but-out-of-window payer signature with 401 invalid_payer_sig
		// and hands back its own clock as node_time. Without this the dispatcher
		// launders that 401 into "operators_busy" — and the same skewed clock
		// signs every candidate, so a skewed proxy would fail every reserve with
		// no recovery. Re-stamp payer_issued_at to the node's clock, re-sign,
		// re-marshal, and retry once against the same operator. Only when we
		// signed (an unsigned 401 can't be fixed here).
		var skew *payerSigSkewError
		if c.Signer != nil && req.PayerAddr != "" && errors.As(err, &skew) {
			if body2, mErr := signAndMarshal(skew.nodeTime); mErr == nil {
				rt, err = c.reserveAttempt(ctx, op, req, body2, ephemeral, sealRecipient, hop)
			}
		}
	}
	// Unsigned, or still skewed after the resync: the 401 is an ordinary refusal.
	var skew *payerSigSkewError
	if errors.As(err, &skew) {
		return nil, skew.http
	}
	if err != nil {
		// A bad_reserve_envelope means the node couldn't age-open the body (the
		// recipient we sealed to is defunct — a stale-but-unexpired ephemeral).
		// Wrap (don't flatten) the sentinel so the dispatcher can detect it via
		// IsBadReserveEnvelope and self-heal (re-probe + retry) before skipping.
		if errors.Is(err, errBadReserveEnvelope) {
			return nil, fmt.Errorf("reserve: %w", errBadReserveEnvelope)
		}
		return nil, err
	}
	handedBack = true
	return rt, nil
}

// reserveAttempt seals body to sealRecipient and runs one POST
// /v1/zs/reserve against op (optionally via hop), parses + verifies the
// response, and pins sealRecipient into the returned ReservedTicket. It is
// the single-attempt core Reserve calls once (anchor/ephemeral chosen by
// the caller) and a second time for retry-to-anchor. A node-side
// bad_reserve_envelope 400 comes back as errBadReserveEnvelope so Reserve
// can decide whether to retry; every other failure is returned verbatim.
//
// ephemeral is the proxy's reply-to identity (its recipient is already in
// req.ProxyRecipient and it unwraps the response key); body is the
// pre-marshaled req. Re-marshaling is avoided across attempts — only the
// seal recipient differs.
func (c *HTTPReserveClient) reserveAttempt(
	ctx context.Context,
	op Operator,
	req ticket.ReserveRequest,
	body []byte,
	ephemeral *age.X25519Identity,
	sealRecipient age.Recipient,
	hop *RelayHop,
) (*ReservedTicket, error) {
	// Seal the reserve body to the chosen recipient. With single-hop relaying
	// live, a plaintext reserve would expose the caller's payer_addr to the
	// relay; sealing it — confidentiality-only, no ticket to bind yet — closes
	// that link while the relay still forwards the opaque bytes. The node seals
	// its response back to the proxy_recipient carried inside this plaintext.
	sealed, err := wire.SealReserveRequest(body, sealRecipient)
	if err != nil {
		return nil, fmt.Errorf("seal reserve request: %w", err)
	}

	url := strings.TrimRight(op.BaseURL, "/") + reservePath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(sealed))
	if err != nil {
		return nil, fmt.Errorf("build reserve request: %w", err)
	}
	httpReq.Header.Set("Content-Type", wire.SealedReserveContentType)
	// A 200 comes back sealed to our ephemeral; errors stay plaintext JSON so we
	// can report why the reserve failed.
	httpReq.Header.Set("Accept", wire.SealedReserveResponseContentType+", "+ticket.ReserveContentType)
	// In transport-privacy mode, route the reserve through the relay hop. The
	// body and Content-Type are unchanged — the relay forwards them verbatim
	// to the target's reserve endpoint. No-op when hop is nil.
	if err := ApplyRelay(httpReq, hop, reservePath, http.MethodPost); err != nil {
		return nil, fmt.Errorf("apply relay: %w", err)
	}

	client := c.HTTPClient
	if client == nil {
		client = defaultReserveHTTPClient
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		// No response arrived, so there is no status or code to classify on.
		// Status 0 is transient.TransportFailureStatus, which classifies as
		// retryable/unattributable — the caller (which knows whether it dialed a
		// relay or the target) narrows the attribution from context.
		return nil, &ReserveHTTPError{Message: err.Error(), Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxOperatorResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read reserve response: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		// Carry the node's code: the dispatch loop needs it to tell the one
		// re-askable 429 from the three that must not be re-asked. See BusyError.
		return nil, &BusyError{
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
			Code:       openAIErrorCode(respBody),
		}
	}
	if resp.StatusCode == http.StatusBadRequest {
		// Node-side sizing rejections (max_output_tokens > the operator's
		// per-model cap, or max_output_tokens >= context_window) come
		// back as 400 with an OpenAI-shaped body and a known code. Tag
		// them as *SizeError so dispatch can prefer
		// context_length_exceeded over operators_busy when every
		// candidate refuses for size. Other 400s (malformed envelope,
		// invalid_payer_addr, etc.) keep falling through to the generic
		// error — they're operator-environment problems, not client-
		// retryable signals.
		if se := parseSizeError(respBody); se != nil {
			return nil, se
		}
		// A bad_reserve_envelope 400 means the node could not age-open the
		// sealed body — the recipient's private half is gone (stale ephemeral
		// after a node restart). Surface the sentinel so Reserve can retry to
		// the on-chain anchor when this attempt used the ephemeral recipient.
		if openAIErrorCodeIs(respBody, badReserveEnvelopeCode) {
			return nil, errBadReserveEnvelope
		}
	}
	if resp.StatusCode == http.StatusForbidden {
		// Payer-scoped refusal (today: the daily free-ticket allowance is spent).
		// Enforced on chain against the payer, so failing over to the next
		// operator cannot help — surface it as terminal instead of laundering it
		// into operators_busy. Retry-After carries the node's reset estimate.
		if pe := parsePayerRefusal(respBody, parseRetryAfter(resp.Header.Get("Retry-After"))); pe != nil {
			return nil, pe
		}
	}
	if resp.StatusCode == http.StatusUnauthorized {
		// The node rejects a present-but-out-of-window payer signature with 401
		// invalid_payer_sig, embedding its clock as node_time so a skewed signer
		// can re-stamp and re-sign. Surface it as *payerSigSkewError so Reserve
		// can resync + retry once — otherwise the dispatcher would launder this
		// into operators_busy. A 401 without a parseable node_time (or another
		// code) falls through to the generic error.
		var env struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(respBody, &env) == nil && env.Error.Code == "invalid_payer_sig" {
			if nt, ok := parseNodeTime(env.Error.Message); ok {
				return nil, &payerSigSkewError{nodeTime: nt, http: &ReserveHTTPError{
					Status:         resp.StatusCode,
					Code:           env.Error.Code,
					RetryAfter:     parseRetryAfter(resp.Header.Get("Retry-After")),
					Message:        truncate(string(respBody), 256),
					RelayHopMarked: resp.Header.Get(wire.RelayHopHeader) != "",
				}}
			}
		}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &ReserveHTTPError{
			Status:     resp.StatusCode,
			Code:       openAIErrorCode(respBody),
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
			Message:    truncate(string(respBody), 256),
			// Whether the relay's own handler produced this. On a code-less
			// 5xx it is the difference between "the relay forwarded and this
			// is the target's gateway" and "we never got past the relay's
			// front door" — see transient.NarrowRelayed.
			RelayHopMarked: resp.Header.Get(wire.RelayHopHeader) != "",
		}
	}

	// The 200 body is age-sealed to the ephemeral recipient we declared as
	// proxy_recipient inside the sealed request — a relay saw neither, so it
	// forwarded opaque bytes and never read presigned_open_txn's payer address.
	plaintextResp, err := wire.OpenReserveResponse(respBody, ephemeral)
	if err != nil {
		return nil, fmt.Errorf("open reserve response: %w", err)
	}
	var parsed ticket.ReserveResponse
	if err := json.Unmarshal(plaintextResp, &parsed); err != nil {
		return nil, fmt.Errorf("parse reserve response: %w", err)
	}

	if err := parsed.Ticket.Verify(op.TicketSigningKey); err != nil {
		return nil, fmt.Errorf("verify ticket: %w", err)
	}
	if err := validateTicketShape(&parsed.Ticket, op, req); err != nil {
		return nil, fmt.Errorf("validate ticket: %w", err)
	}
	if parsed.WrappedResponseKey == "" {
		return nil, errors.New("reserve response missing wrapped_response_key")
	}
	key, err := wire.UnwrapResponseKey(parsed.WrappedResponseKey, ephemeral)
	if err != nil {
		return nil, fmt.Errorf("unwrap response key: %w", err)
	}

	// Reserve-time commit_k check: the K the node wrapped in
	// wrapped_response_key MUST hash to the commitment baked into the
	// (already signature-verified) ticket. Run it BEFORE the caller composes
	// and submits open() so a node that committed sha256(K_real) but wrapped a
	// different K can't make us burn tx fees + lock escrow on a request its own
	// admission tag will then reject. This mirrors the TS SDK's reserve-time
	// check (sdk/src/reserve.ts, via verifyCommitK in sdk/src/verify.ts) and
	// this package's response-time verifyCommitK (dispatch.go) — same
	// base64(sha256(K)) == ticket.commit_k comparison, using the shared
	// ticket.CommitResponseKey primitive. SPEC §3a.
	if commit := ticket.CommitResponseKey(key); base64.StdEncoding.EncodeToString(commit[:]) != parsed.Ticket.CommitK {
		clear(key[:])
		return nil, errors.New("reserve commit_k mismatch: wrapped_response_key does not hash to ticket.commit_k")
	}

	var presigned []types.SignedTxn
	if parsed.PreSignedOpenTxn != "" {
		presigned, err = escrow.DecodeOpenGroup(parsed.PreSignedOpenTxn)
		if err != nil {
			clear(key[:])
			return nil, fmt.Errorf("decode presigned open group: %w", err)
		}
	}

	return &ReservedTicket{
		Ticket:             &parsed.Ticket,
		ResponseKey:        key,
		AgeIdentity:        ephemeral,
		AlgoUSDPrice:       parsed.AlgoUSDPrice,
		PreSignedOpenGroup: presigned,
		SealRecipient:      sealRecipient,
	}, nil
}

// openAIErrorCodeIs reports whether body is an OpenAI-shaped error envelope
// whose error.code equals want. Returns false on a malformed / non-error
// body. Kept narrow (no message extraction) since the only caller just
// needs the code match to gate retry-to-anchor.
func openAIErrorCodeIs(body []byte, want string) bool {
	return openAIErrorCode(body) == want
}

// openAIErrorCode reads the OpenAI-shaped `error.code` off a response body,
// returning "" for a body that isn't JSON, isn't that shape, or carries no code
// — which is itself the signal that an intermediary (CDN / ingress / LB), not
// the node, wrote the response. transient.Classify keys on exactly that
// distinction, so the empty return is meaningful, not merely a parse failure.
func openAIErrorCode(body []byte) string {
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return ""
	}
	return env.Error.Code
}

// validateTicketShape checks that the ticket's fields reflect what we
// asked for and what the registered operator is. Signature validity is
// checked separately via Ticket.Verify — this function catches
// cases where the signature happens to be valid (e.g. operator signed
// garbage with their legit key) but the content is inconsistent.
func validateTicketShape(t *ticket.Ticket, op Operator, req ticket.ReserveRequest) error {
	if t.OperatorID != op.ID {
		return fmt.Errorf("ticket operator id %d != registry operator id %d", t.OperatorID, op.ID)
	}
	// The routing primary key is (operator id, node id) — a ticket bound to a
	// different node than the one we selected can't be trusted to settle (open()
	// snapshots (operatorId, nodeId) and resolves THAT node's signing key) and
	// would mis-attribute per-node metrics/affinity. The signature can't catch a
	// node-id-only mismatch when the operator's nodes share a signing key, so
	// check the field explicitly. Mirrors the client's validateTicketShape.
	if t.NodeID != op.NodeID {
		return fmt.Errorf("ticket node id %d != registry node id %d", t.NodeID, op.NodeID)
	}
	if t.Model != req.Model {
		return fmt.Errorf("ticket model %q != request model %q", t.Model, req.Model)
	}
	// input_count is deliberately not compared: the node caps it at
	// context_window − max_output_count (SPEC §3a), and an older node also
	// floored it at min_input_count, so an honest ticket can differ from the
	// request. VerifyTicketPrice's input_count_bound is what stops a node
	// inflating it. That bound allows the payer's own count plus 10%, so it
	// refuses a short request from an older node whose floor was set above 256.
	if t.MaxOutputCount != req.MaxOutputCount {
		return fmt.Errorf("ticket max_output_tokens %d != request %d", t.MaxOutputCount, req.MaxOutputCount)
	}
	if t.Stream != req.Stream {
		return fmt.Errorf("ticket stream %v != request %v", t.Stream, req.Stream)
	}
	if t.ExpiresAt <= time.Now().Unix() {
		return fmt.Errorf("ticket expires_at %d is in the past", t.ExpiresAt)
	}
	if t.TicketID == "" {
		return errors.New("ticket_id is empty")
	}
	if t.CommitK == "" {
		return errors.New("commit_k is empty")
	}
	// The node guarantees min_price <= max_price at reserve time (it
	// bumps max_price to cover min_price for tiny paid requests).
	// Reject a ticket that violates the invariant — it would either
	// underfund escrow or signal a misbehaving operator.
	if t.MinPrice > t.MaxPrice {
		return fmt.Errorf("ticket min_price %d > max_price %d (invariant violated)", t.MinPrice, t.MaxPrice)
	}
	return nil
}

// parseRetryAfter interprets the HTTP Retry-After header as a duration.
// Per RFC 7231 the value may be either a delta-seconds integer or an
// HTTP-date; we only parse delta-seconds (what the node emits). It reads the
// node's value up to a day, because a free-ticket allowance resets on that
// scale and the caller is told when. Where one node's hint becomes the
// caller's wait otherwise, nodeRetryHint caps it.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return 0
	}
	const maxRetryAfter = 24 * time.Hour
	// Compared before the multiply, which overflows int64 past ~292 years.
	if n >= int(maxRetryAfter/time.Second) {
		return maxRetryAfter
	}
	return time.Duration(n) * time.Second
}

// maxNodeRetryHint caps one node's Retry-After where it becomes the wait an
// Error tells its caller to honor: a single hostile or misconfigured node must
// not park the caller for a day. The free-ticket reset (PayerRefusalError) is
// enforced on chain against the payer, so it keeps its full value.
const maxNodeRetryHint = 5 * time.Minute

func nodeRetryHint(d time.Duration) time.Duration { return min(d, maxNodeRetryHint) }

// NodeRetryAfter is the wait one node's reply asks for, as its Retry-After
// header reads and capped at maxNodeRetryHint. A server passing a node's
// reply through sets this in place of the node's own header, or the cap is
// lost on the way out.
func NodeRetryAfter(h http.Header) time.Duration {
	return nodeRetryHint(parseRetryAfter(h.Get("Retry-After")))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
