/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package ticket

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// ReserveContentType is the Content-Type for a POST /v1/zs/reserve *error*
// response body — plaintext OpenAI-shaped JSON, which carries no ticket and no
// payer.
//
// Both bodies of a successful reserve are sealed. The request rides age-sealed
// to the target under wire.SealedReserveContentType (protocol 3.0), and since
// 8.0 the 200 response rides age-sealed to the caller's proxy_recipient under
// wire.SealedReserveResponseContentType — a plaintext response handed a relay
// the payer address inside presigned_open_txn. The inner shapes (ReserveRequest,
// ReserveResponse) are unchanged; see wire.SealReserveRequest /
// wire.OpenReserveRequest / wire.SealReserveResponse / wire.OpenReserveResponse
// and SPEC.md § 3a, § 3f.
const ReserveContentType = "application/json"

// ReserveRequest is the proxy → node body sent to /v1/zs/reserve to ask whether
// the node can accept a prompt of the described shape.
//
// SPEC.md § 3a "Request" is authoritative for every field's semantics and
// documents each one in full. Noted here only where the Go side adds something
// the spec table doesn't:
//
//   - InputCount is a conservative upper bound, not a tokenizer output, so
//     unknown models route without per-model encoding config. MaxOutputCount is
//     exact. See § 3a "Input-token bound".
//   - ProxyRecipient is required — validateReserveRequest refuses an empty one
//     with 400 invalid_reserve. Inside CanonicalBytes it doubles as the reserve
//     REPLAY NONCE, and the node records it on the ticket so admission can
//     enforce the reply-to binding (402 reply_to_mismatch).
//   - PayerAddr must be known at reserve time so the node can pre-compute the
//     open() group hash and sign gtxn[1] bound to the proxy's specific
//     usdcPayment sender (§ 3a "Operator authentication").
//
// The image and payer-sig fields below ride the sealed reserve request ONLY —
// none are part of Ticket.CanonicalBytes, so they add no wire-format change.
type ReserveRequest struct {
	Model          string `json:"model"`
	InputCount     uint64 `json:"input_count"`
	MaxOutputCount uint64 `json:"max_output_count"`
	Stream         bool   `json:"stream"`
	ProxyRecipient string `json:"proxy_recipient,omitempty"`
	PayerAddr      string `json:"payer_addr,omitempty"`

	// ImageToolBudget / ImageEditToolBudget cap how many images the
	// zs_image_generation / zs_image_edit built-ins may produce across the whole
	// tool loop. The budget rides MaxPrice additively (max_n × per-image cap);
	// the raw counts are passed so the node can enforce per-tool consumption
	// in-loop. 0 ⇒ the tool is unusable for this request even if the model calls
	// it. See SPEC.md "In-loop image tools".
	ImageToolBudget     uint64 `json:"image_tool_budget,omitempty"`
	ImageEditToolBudget uint64 `json:"image_edit_tool_budget,omitempty"`
	// ImageN / ImageSize / ImageQuality describe a dedicated-route image
	// request (/v1/images/{generations,edits}) priced by the parameter-
	// deterministic microUSDC model rather than the synthetic-token factor.
	// When ImageN > 0 and the model advertises a per-image microUSDC rate,
	// the node sizes MaxPrice = imageprice.CostMicroUSDC(rate, ImageN,
	// ImageSize, ImageQuality) directly (InputCount / MaxOutputCount are
	// then unused for sizing). These ride the plaintext reserve only — NOT
	// part of Ticket.CanonicalBytes — so they add no wire-format change.
	// See SPEC.md "Dedicated image route".
	ImageN       uint64 `json:"image_n,omitempty"`
	ImageSize    string `json:"image_size,omitempty"`
	ImageQuality string `json:"image_quality,omitempty"`
	// ImageEdit selects the edit route (/v1/images/edits, EditRate) over the
	// generation route (/v1/images/generations, Rate) when sizing a dedicated
	// image reserve. Ignored unless ImageN > 0.
	ImageEdit bool `json:"image_edit,omitempty"`
	// PayerSig / PayerIssuedAt authenticate PayerAddr: PayerSig is
	// base64(Ed25519 over ReserveSigDigest) produced by the key underneath
	// PayerAddr, and PayerIssuedAt is the unix-second timestamp the signature
	// commits to (the start of the [issued_at, issued_at+MaxReserveSigAge]
	// validity window). Sealing the reserve buys confidentiality, not
	// authentication — anyone can craft a valid sealed body to the node's
	// published ephemeral recipient — so without this the per-account limiter
	// keys on an unproven claim an attacker rotates or spoofs at will (design
	// §2, §4). The signature additionally binds the target (operator_id,
	// node_id) and proxy_recipient as *unsent* signed context (see
	// CanonicalBytes) — they are not JSON fields. Both are additive inside the
	// sealed body: an 8.0 node ignores them, and a node accepts a missing
	// signature until zs.require_payer_sig flips (verify-if-present). Ride the
	// sealed reserve request only — NOT part of Ticket.CanonicalBytes. See
	// SPEC.md § 3a "Reserve-request signature".
	PayerSig      string `json:"payer_sig,omitempty"`       // base64(Ed25519 over ReserveSigDigest)
	PayerIssuedAt int64  `json:"payer_issued_at,omitempty"` // unix seconds; signed
	// InputBoundVersion names the tokenize bound the caller used to compute
	// InputCount, so the node enforces the inference-time input budget with the
	// SAME function. Omitted / 0 means version 1.
	//
	// This has to be explicit rather than inferred, because bound v2 is not
	// uniformly smaller than v1: it is tighter on prose, tool schemas and
	// images, but deliberately LARGER on the classes v1 under-counts (base64,
	// hex, UUID-dense text, emoji, embedded JSON). A node that simply measured
	// with its newest bound would reject a correctly-sized v1 caller whose body
	// happens to be CJK or base64 — an outage caused purely by upgrading. With
	// the version on the request, a 9.2 node serves 9.1 and 9.2 callers
	// identically well.
	//
	// Rides the sealed reserve request only — NOT part of Ticket.CanonicalBytes,
	// so it is additive and changes no signature. A caller only sets it after
	// wire.UsesTightInputBound confirms the target advertises >= 9.2. See
	// SPEC.md § 3a "Input-token bound".
	InputBoundVersion uint8 `json:"input_bound_version,omitempty"`
}

// reserveSigningTag domain-separates the reserve-request payer signature from
// Ticket / UsageReceipt / EphemeralAdvertisement signatures and any other
// Ed25519 the system may introduce. The trailing NUL matches the whole family
// (zs-ticket-v2\x00, zs-receipt-v2\x00, zs-ephemeral-v1\x00,
// zs-admission-v1\x00) — self-terminating in any concatenation.
const reserveSigningTag = "zs-reserve-v1\x00"

// MaxReserveSigAge is the short validity window a verifier enforces on a
// payer signature: a reserve is immediate and per-request, so the window is
// deliberately tight (contrast MaxEphemeralLifetime = 40m). Combined with the
// per-node seen-ProxyRecipient replay set, it bounds how long a captured
// sealed body can be replayed.
const MaxReserveSigAge = 60 * time.Second

// DefaultReserveSkew is the clock-skew tolerance a verifier applies to both
// window edges (not-before and expiry). IssuedAt is stamped on consumer
// devices, so some slack is mandatory; the node echoes node_time in the 401 so
// a skewed-clock client can resync and re-sign once rather than fail opaquely.
const DefaultReserveSkew = 30 * time.Second

// ErrReserveSigExpired is returned by Verify when the signature is valid but
// the [IssuedAt, IssuedAt+MaxReserveSigAge] window has passed (now beyond it +
// skew). A sentinel so the node distinguishes a stale-but-genuine signature
// (client clock lagging → 401 with node_time for a one-shot resync) from a
// forgery.
var ErrReserveSigExpired = errors.New("reserve signature expired")

// CanonicalBytes returns the unambiguous byte sequence the payer signature
// covers — the *signed subset* of the reserve, plus the target (operatorID,
// nodeID) as signed context. Encoding rules match Ticket.CanonicalBytes:
// domain tag, then length-prefixed strings and fixed-width big-endian
// numbers, with the boolean as a single 0/1 byte — independent of any JSON
// encoder so proto/ts reproduces the exact bytes.
//
// LOCKED layout (any change requires a vectors regeneration + the matching TS
// edit): reserveSigningTag ‖ lenStr(PayerAddr) ‖ u64(OperatorID) ‖
// u64(NodeID) ‖ lenStr(Model) ‖ u64(InputCount) ‖ u64(MaxOutputCount) ‖
// bool(Stream) ‖ lenStr(ProxyRecipient) ‖ i64(IssuedAt).
//
// Target binding — (operatorID, nodeID) are NOT wire fields; both ends already
// know them out of band (the signer from the node it routes to, the verifier
// from its own config), so they enter as parameters. Without this a malicious
// first-recipient node could re-seal a valid signed reserve to a *sibling*
// node's published ephemeral recipient and replay it there inside the window —
// burning the payer's quota / slot cap and manufacturing abandon strikes at
// nodes the payer never contacted. The per-node seen-recipient set cannot
// catch a cross-node replay; the binding does. ProxyRecipient is a per-request
// fresh X25519 recipient, so it doubles as the replay nonce. IssuedAt is the
// tail so the signed window is tamper-evident. PayerSig and the recovered
// pubkey are excluded (the sig is what we compute; the pubkey is recovered
// from PayerAddr). The image / (future video) fields are excluded, mirroring
// Ticket.CanonicalBytes — the age seal already gives the ciphertext integrity,
// so the signature's job is binding, not integrity.
func (r *ReserveRequest) CanonicalBytes(operatorID, nodeID uint64) []byte {
	b := make([]byte, 0, 160)
	b = append(b, reserveSigningTag...)
	b = appendLenStr(b, r.PayerAddr)
	b = appendU64(b, operatorID)
	b = appendU64(b, nodeID)
	b = appendLenStr(b, r.Model)
	b = appendU64(b, r.InputCount)
	b = appendU64(b, r.MaxOutputCount)
	if r.Stream {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	b = appendLenStr(b, r.ProxyRecipient)
	b = appendI64(b, r.PayerIssuedAt)
	return b
}

// ReserveSigDigest returns sha256(CanonicalBytes(operatorID, nodeID)) — the
// 32-byte value both Sign and Verify feed to ed25519. CanonicalBytes already
// prepends the "zs-reserve-v1\x00" domain tag so the digest is cross-protocol
// safe. Exposed (like TicketSigDigest / EphemeralSigDigest) so the signing
// payload stays single-source.
func ReserveSigDigest(r *ReserveRequest, operatorID, nodeID uint64) [sha256.Size]byte {
	return sha256.Sum256(r.CanonicalBytes(operatorID, nodeID))
}

// Sign populates r.PayerSig with an Ed25519 signature over
// ReserveSigDigest(r, operatorID, nodeID), produced by the key underneath
// payerAddr. It sets r.PayerAddr = payerAddr first so the signed identity can
// never diverge from the signing key's address. The caller must have already
// set r.Model / r.InputCount / r.MaxOutputCount / r.Stream / r.ProxyRecipient
// and r.PayerIssuedAt — the signature commits to all of them plus the target
// (operatorID, nodeID). operatorID / nodeID are the node this reserve is being
// sent to (proxy: hayai.Operator.ID/NodeID; client: the RoutableNode it
// reserves against). Mirrors Ticket.Sign / EphemeralAdvertisement.Sign.
func (r *ReserveRequest) Sign(ctx context.Context, signer BytesSigner, payerAddr string, operatorID, nodeID uint64) error {
	if signer == nil {
		return errors.New("reserve sign: signer is nil")
	}
	r.PayerAddr = payerAddr
	digest := ReserveSigDigest(r, operatorID, nodeID)
	sig, err := signer.SignBytes(ctx, payerAddr, digest[:])
	if err != nil {
		return fmt.Errorf("reserve sign: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("reserve sign: signer returned %d-byte signature, want %d", len(sig), ed25519.SignatureSize)
	}
	r.PayerSig = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// Verify checks that r.PayerSig is a valid Ed25519 signature of
// ReserveSigDigest(r, operatorID, nodeID) under pub, and that the signed
// [IssuedAt, IssuedAt+MaxReserveSigAge] window is live within skew. pub is
// recovered by the caller from r.PayerAddr (DecodeAlgorandAddress); operatorID
// / nodeID are the verifying node's OWN configured identity, never trusted
// from the wire — a signature presented to the wrong node simply fails to
// verify (target binding, see CanonicalBytes).
//
// Ordering mirrors EphemeralAdvertisement.Verify: (1) decode + ed25519.Verify,
// so a forgery fails generically and the timestamps below are authentic before
// any policy keys off them; (2) not-before — reject a future-dated IssuedAt
// (a payer cannot pre-sign); (3) the short validity window last, surfacing
// ErrReserveSigExpired so the node can 401 a stale-but-genuine signature with
// node_time for a one-shot client resync rather than treat it as a forgery.
// now is injected so callers can test boundaries deterministically.
func (r *ReserveRequest) Verify(pub ed25519.PublicKey, operatorID, nodeID uint64, now time.Time, skew time.Duration) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid ed25519 public key length %d", len(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(r.PayerSig)
	if err != nil {
		return fmt.Errorf("decode reserve sig: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid ed25519 signature length %d", len(sig))
	}
	digest := ReserveSigDigest(r, operatorID, nodeID)
	if !ed25519.Verify(pub, digest[:], sig) {
		return errors.New("reserve signature verification failed")
	}

	// Signed values are now authentic — enforce the window.
	issuedAt := time.Unix(r.PayerIssuedAt, 0)
	if issuedAt.After(now.Add(skew)) {
		return fmt.Errorf("reserve signature not yet valid: issued_at %d is in the future", r.PayerIssuedAt)
	}
	if now.After(issuedAt.Add(MaxReserveSigAge).Add(skew)) {
		return ErrReserveSigExpired
	}
	return nil
}

// ReserveResponse is the node → proxy body returned from a successful
// reserve. On refusal the node returns HTTP 429 with a Retry-After
// header and no body (or an OpenAI-shaped error body; the status code
// is authoritative).
//
// WrappedResponseKey is base64(age_encrypt(K_response, ProxyRecipient))
// — the same primitive as X-Zs-Response-Key, just delivered at
// reserve time so the proxy has K_response before it builds the
// encrypted request (and therefore before it can compute the
// admission tag). Empty when ProxyRecipient was empty. See SPEC.md
// § 3a.
//
// AlgoUSDPrice is the ALGO/USD exchange rate the node observed at
// reserve time. It is NOT used to derive the ticket's InputRate /
// OutputRate / MaxPrice — those are microUSDC, converted directly from
// the operator's USD/1M config (1 USDC ≈ $1). It is included so the
// proxy / TUI can express the *ALGO* network fees the operator
// commits at open + atomic-settle (~8,000 µALGO: 2 at open + 6 at
// settle) in USD. Omitted when
// the operator's oracle was unavailable at reserve time; inference
// pricing is unaffected.
//
// PreSignedOpenTxn is base64(msgpack(SignedTxn)) — the operator's
// pre-signed gtxn[1] of the 2-tx open() group. The proxy assembles
// gtxn[0] (usdcPayment) with payerAddr-as-sender and fee=0, then submits
// both together. There is no feePayment leg — the box MBR is drawn from
// the payer's prepaid pool at open(). The operator's gtxn[1] over-fees
// (2 × minTxnFee) so the entire group's outer fees come out of the
// operator's account, not the payer's. See SPEC.md § 3a.
//
// PreSignedOpenTxn is why the whole response is sealed: the encoded group
// names the payer as gtxn[0]'s sender and again as open()'s payerAddr ABI
// arg, so anything that can read this struct reads the payer address.
type ReserveResponse struct {
	Ticket             Ticket  `json:"ticket"`
	WrappedResponseKey string  `json:"wrapped_response_key,omitempty"`
	AlgoUSDPrice       float64 `json:"algo_usd_price,omitempty"`
	PreSignedOpenTxn   string  `json:"presigned_open_txn,omitempty"`
}
