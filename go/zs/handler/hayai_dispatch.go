/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/age"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/pricing"
	protorelay "github.com/TxnLab/zerosignal/go/relay"
	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/steering"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/transient"
	"github.com/TxnLab/zerosignal/go/wire"
	hayai "github.com/TxnLab/zerosignal/go/zs"
	"github.com/TxnLab/zerosignal/go/zs/handler/transform"
	"github.com/TxnLab/zerosignal/go/zs/tokenize"
)

// maxImageToolBudgetPerRequest caps a single request's hayai image-tool
// budget (total images per tool across the whole /v1/responses turn). It
// bounds the untrusted client max_n before it sizes the reserve: the node
// delegates this clamp to the proxy (it records the raw counts verbatim and
// honors them in its tool loop — see node reserve.go "the proxy already ...
// validated" and handlers.go "budgets are tiny (proxy clamps max_n)"). Left
// unbounded, a hostile max_n would (a) overflow the synthetic-token multiply
// in the reserve loop, wrapping MaxOutputTokens — and thus the escrowed
// MaxPrice — down to a tiny value while the node still produces the huge
// image budget (free image generation), and (b) let a client size an absurd
// escrow. Generous for legitimate agentic image use (most turns produce a
// handful); the node applies its own per-call max_n underneath. Defense-in-
// depth, not a product limit — lift to config if a real workload needs more.
const maxImageToolBudgetPerRequest uint64 = 64

// dispatchHayai runs the two-phase admission flow:
//
//  1. Select candidate operators from the registry, preferring an
//     affinity-matched operator when the request contains tool_call_id
//     continuations (§ 3a "Operator affinity").
//  2. For each candidate: POST /v1/zs/reserve; on 429 move on (per
//     affinity policy); on success verify the ticket signature + shape.
//  3. Compose + submit a Payment + escrow.open group via the wallet.
//     Submit the sealed request to the chosen operator's BaseURL carrying
//     the returned ticket_id and the app-call txid.
//  4. On response decrypt: verify commit_k == sha256(K), and scan the
//     plaintext for tool_calls[].id to record the operator in the
//     affinity cache for the next turn.
//
// If every candidate refuses, the client gets a 503 with Retry-After
// propagated from the shortest operator hint — the admission layer is
// doing its job and no payment has happened.
func (s *Server) dispatchHayai(w http.ResponseWriter, r *http.Request, endpoint string, body []byte, format clientFormat) {
	ctx := r.Context()

	isImage := endpoint == endpointImages
	isImageEdit := endpoint == endpointImageEdits

	// Parse the caller's OpenRouter-style routing preferences from the body's
	// `provider` object (advisory — absent/malformed ⇒ defaults, never fails the
	// request). Parsed from the ORIGINAL body, BEFORE any pre-seal mutation
	// strips/rewrites it, so pickCandidates can guide selection while the sealed
	// body never carries `provider` to the node/upstream. Image-edit bodies are
	// multipart (not JSON), so this no-ops to defaults there — provider routing
	// isn't offered on that route yet.
	routingPrefs := selection.ExtractRoutingPreferences(body)

	// Default `store` to false when the client omitted it; preserve
	// any explicit caller value (true or false). Caller-controlled per
	// SPEC.md "Upstream retention". Doing it here means the AAD and
	// admission tag commit to the post-mutation body. The node applies
	// the same default. Fail-open on parse failure — the node will
	// reject malformed bodies anyway.
	//
	// Skipped for image-edits: the body is multipart/form-data, not
	// JSON, so DefaultStoreFalse would silently no-op (parse-fail). Per
	// SPEC.md "Upstream retention" the store knob only applies to
	// chat/responses anyway — image routes have no upstream retention
	// concept.
	if !isImageEdit {
		// Strip `provider` pre-seal: it's a proxy-only routing hint and must not
		// reach the node/upstream, which would reject the unknown field (strict
		// vLLM/SGLang pydantic) — same pre-seal discipline as the mutators below,
		// so the AAD/admission tag commit to the cleaned body. Run first so the
		// remarshaling mutators don't carry `provider` forward.
		if stripped, err := inject.DropRoutingPreferences(body); err != nil {
			s.log.Warn("routing-preferences strip failed; forwarding body unchanged", slog.Any("err", err))
		} else {
			body = stripped
		}
		if augmented, err := inject.DefaultStoreFalse(body); err != nil {
			s.log.Warn("store default injection failed; forwarding body unchanged", slog.Any("err", err))
		} else {
			body = augmented
		}
		// Normalize an empty `tools: []` (and a dangling tool_choice) out of the
		// body before sealing. OpenAI tolerates it, but stricter upstreams
		// (vLLM/SGLang pydantic validation) reject it — JetBrains/Koog sends it
		// on a plain chat turn, which would otherwise 422 at the node. Pre-seal,
		// like DefaultStoreFalse, so the AAD/admission tag commit to the cleaned
		// body. Empty tools ≡ no tools, so this is semantically a no-op.
		if stripped, err := inject.DropEmptyTools(body); err != nil {
			s.log.Warn("empty-tools normalization failed; forwarding body unchanged", slog.Any("err", err))
		} else {
			body = stripped
		}
		// Strip `prompt_cache_key` pre-seal. It is a client-chosen upstream cache
		// hint, but clients derive it from what does NOT change across a
		// conversation (Hermes Agent: a digest of session id + system prompt +
		// tool schemas), so one value is stable for a session and identical
		// whichever operator serves a given turn. Not a closed channel reopened —
		// target selection here is deterministic, and an operator that serves a
		// turn already sees the history and the payer — but an exact-match token
		// that survives truncation and compaction is a cheaper join than either,
		// and nothing past this point needs it. See inject.DropPromptCacheKey.
		if stripped, err := inject.DropPromptCacheKey(body); err != nil {
			s.log.Warn("prompt-cache-key strip failed; forwarding body unchanged", slog.Any("err", err))
		} else {
			body = stripped
		}
	}

	var model string
	var imageN int
	var imageSize, imageQuality string
	var imageEditStream bool
	switch {
	case isImageEdit:
		m, n, size, quality, stream, err := parseImageEditMultipart(r.Header.Get("Content-Type"), body)
		if err != nil {
			writeError(w, newError("bad_image_edit_request", err.Error()))
			return
		}
		model = m
		imageN = n
		imageSize, imageQuality = size, quality
		imageEditStream = stream
	case isImage:
		model = hayai.ExtractModel(body)
		if model == "" {
			writeError(w, newError("missing_model", "request body has no model field"))
			return
		}
		n, size, quality, err := parseImageRequestN(body)
		if err != nil {
			writeError(w, newError("bad_image_request", err.Error()))
			return
		}
		imageN = n
		imageSize, imageQuality = size, quality
	default:
		model = hayai.ExtractModel(body)
		if model == "" {
			writeError(w, newError("missing_model", "request body has no model field"))
			return
		}
	}

	// Note the model as in-demand so the background refresh prioritizes probing
	// its servers under bounded probing. Advisory; no-op on static
	// registries.
	s.registryProvider.RecordModelDemand(model)

	// Streaming is opt-in via stream:true (OpenAI-compatible). For JSON
	// bodies (chat/responses/image-generations) streamableRequest peeks the
	// field; the image-edit body is multipart, so its stream flag comes from
	// the multipart parse above. When set, the SSE-pump branch forwards the
	// node's sealed image progress/preview/completed frames unchanged.
	var wantsStream bool
	switch {
	case isImageEdit:
		wantsStream = imageEditStream
	default:
		wantsStream = streamableRequest(body)
	}

	// TEE requirement: per-request opt-in via the X-Zs-Require-TEE
	// header (a client-supplied transport-time signal — does not
	// traverse the sealed envelope) plus a config-driven blanket
	// policy for sensitive models. When either fires, pickCandidates
	// drops non-attested operators after sizing.
	//
	// Resolved here, ahead of the estimate, because the max_output clamp below
	// has to know which operators this request could actually reach before it
	// reads their declared ceilings.
	requireTEE := strings.TrimSpace(r.Header.Get("X-Zs-Require-TEE")) != "" ||
		s.cfg.teeRequired(model)

	var est tokenize.Estimate
	if !isImage && !isImageEdit {
		// Lower an over-large caller ceiling to what the pool can actually serve,
		// BEFORE the estimate reads it. `max_tokens` is an upper BOUND on
		// generation, not a demand, so a caller asking for more than any operator
		// caps at is still served correctly by the most generous one — it gets at
		// most what it asked for, and the escrow shrinks rather than grows. Left
		// unclamped the bound acts as an eligibility predicate instead: a tool
		// shipping a model card more generous than anything advertised (a
		// third-party chat app sending max_tokens=65536 at a pool capped at 32768)
		// can never route at all, and the pool-wide miss reports
		// context_length_exceeded — "your conversation is too long" — for a request
		// with abundant context headroom.
		//
		// Pre-seal like the mutators above, so the AAD/admission tag commit to the
		// clamped body and the node forwards the clamped number upstream. Skipping
		// that half would leave the ticket sized for the clamp while the provider
		// is still asked for the original, which either bounces off the provider's
		// own cap or leaves the operator to subsidize the difference.
		//
		// Fails open on a remarshal error — the estimate and Fits then behave
		// exactly as they did before this clamp existed.
		ceiling := s.poolMaxOutput(ctx, model, requireTEE, routingPrefs)
		if clamped, requested, err := inject.ClampMaxOutput(body, ceiling); err != nil {
			s.log.Warn("max_output clamp failed; forwarding body unchanged",
				slog.String("model", model), slog.Any("err", err))
		} else if requested > 0 {
			body = clamped
			// Tell the caller its ceiling moved. Without this the only symptom is
			// a reply that stops at finish_reason:"length" below the budget the
			// tool set, which is indistinguishable from the model simply choosing
			// to stop — and the tool has no way to tell that the proxy, not the
			// model, drew the line. Set before any write (including the error
			// paths below), so a request that gets clamped and STILL misses on
			// context window reports both facts.
			w.Header().Set("X-Zs-Max-Output-Clamped", strconv.FormatUint(ceiling, 10))
			// Debug, not Info: a tool that hardcodes an over-large ceiling in its
			// model card sends one on every single request, so this fires per
			// request for the entire life of that integration. The response header
			// above is the per-request signal; this is for when someone is already
			// looking.
			s.log.Debug("lowered caller max_output_tokens to the pool ceiling",
				slog.String("model", model),
				slog.Uint64("requested", requested),
				slog.Uint64("clamped_to", ceiling))
		}
		var err error
		est, err = s.estimateTokens(model, endpoint, body)
		if err != nil {
			// estimateTokens writes its own structured error response so the
			// client gets unsupported_model / max_output_required shapes that
			// match the reserve endpoint's own errors.
			s.writeTokenizeError(w, endpoint, model, err)
			return
		}
	}

	// Image-tool budgets: a /v1/responses (or chat) client opts the
	// hayai image tools in with a tool_budgets object. We size the reserve
	// to include max_n × the OUTER chat model's synthetic-token factor and
	// pass the raw counts to the node. Parsed and clamped once here, then
	// threaded into pickCandidates (the in-loop image-tool partition) and
	// consumed again by the reserve loop (the per-operator factor lookup) —
	// one parse, one clamp, one source of truth.
	var toolBudgets selection.ImageToolBudgets
	if !isImage && !isImageEdit {
		toolBudgets = selection.ParseToolBudgets(body)
		// Clamp the untrusted client max_n to the proxy's per-request
		// ceiling before it sizes anything — see maxImageToolBudgetPerRequest
		// for why this clamp is the proxy's responsibility and what an
		// unbounded value would do (overflow + free-image extraction).
		if toolBudgets.GenerationMaxN > maxImageToolBudgetPerRequest {
			toolBudgets.GenerationMaxN = maxImageToolBudgetPerRequest
		}
		if toolBudgets.EditMaxN > maxImageToolBudgetPerRequest {
			toolBudgets.EditMaxN = maxImageToolBudgetPerRequest
		}
	}

	sizing := hayai.SizingRequest{
		Model:           model,
		InputTokens:     est.InputTokens,
		MaxOutputTokens: est.MaxOutputTokens,
		// The same body under bound v2, so the sizing filter charges a 9.2
		// operator the real image cost instead of v1's flat 2048x2048 fallback.
		// Without it the filter and the reserve leg disagree: an image request
		// gets routed away from an operator whose window the reserve would then
		// have fit comfortably.
		InputTokensV2: tokenize.InputTokenBoundVersion(body, tokenize.BoundVersion2),
		// When the caller omitted max_output_tokens (and no per-model default
		// applies), size the reserve PER-OPERATOR from each operator's declared
		// capacity rather than the flat fallback — so a small-window operator
		// isn't excluded on a guessed ceiling. Fits, the previous_response_id pin
		// check, and the reserve loop all read these off sizing so they agree.
		DeriveMaxOutput:  est.DeriveMaxOutput,
		MaxOutputCeiling: est.MaxOutputCeiling,
	}
	// Transport-privacy decision (route through a relay, or send direct) is
	// per-request: the config default (Config.Privacy) can be overridden by
	// the caller via `provider.relay` (body) or the X-Zs-Relay header — body
	// wins, header is the fallback for clients that can't set body fields.
	//   - "required" → force a relay (or hard-fail with no_relay_available);
	//     always honored, since it can only strengthen privacy.
	//   - "off"      → skip the relay, send direct (lower latency; the target
	//     sees the proxy's IP); honored only when the operator permits caller
	//     overrides (Config.AllowPrivacyOverride).
	//   - "auto"/absent → keep the config default.
	// The resolved decision governs the SINGLE relay hop chosen per candidate,
	// which carries BOTH the reserve and the inference forward, so `off` is
	// consistent end-to-end. Background discovery probes are unaffected (they're
	// not per-request).
	relayPref := routingPrefs.Relay
	if relayPref == "" {
		relayPref = selection.NormalizeRelay(r.Header.Get("X-Zs-Relay"))
	}
	usePrivacy := resolveUsePrivacy(s.cfg.relayByDefault(), s.cfg.AllowPrivacyOverride, relayPref)
	if relayPref == selection.RelayOff && !s.cfg.AllowPrivacyOverride {
		s.log.Debug("ignoring relay=off override; allow_privacy_override is disabled",
			slog.String("endpoint", endpoint))
	}
	// Forward secrecy is mandatory and unconditional — Reserve always seals only
	// to a verified fresh ephemeral recipient (no anchor fallback, no
	// retry-to-anchor), the candidate loop skips any operator that lacks one,
	// and an all-skip outcome surfaces 503 no_ephemeral_capacity.
	pick, err := s.pickCandidates(ctx, endpoint, model, body, sizing, requireTEE, toolBudgets, routingPrefs)
	if err != nil {
		s.log.Error("operator selection failed",
			slog.String("endpoint", endpoint),
			slog.String("model", model),
			slog.Any("err", err))
		writeError(w, newError("registry", "operator selection failed"))
		return
	}
	if len(pick.Operators) == 0 {
		switch {
		case pick.VersionBlocked:
			// Wire-protocol incompatibility — registry had operators
			// for this model but none advertise a proto_version major
			// matching this build's wire.ProtoVersion. 503 (not 400)
			// because the request shape is fine; the proxy just can't
			// reach any peer speaking the same wire generation. The
			// "no_compatible_operator" code is distinct from
			// no_operator / no_tee_capacity so a client retry-loop
			// can recognize "upgrade required" — a retry against the
			// same fleet will keep failing until either side moves.
			writeError(w, newError("no_compatible_operator",
				"no operator advertises a compatible wire protocol version ("+wire.ProtoVersion+")"))
		case pick.TEEBlocked:
			// Required TEE attestation — none of the otherwise-fitting
			// operators have a current passing verdict. 503 (not 400)
			// because this is a pool-availability failure: the request
			// is well-formed, the proxy just has nothing attested to
			// route it to right now. Distinct from no_operator so the
			// client can retry on a different cadence (TEE recovery
			// usually means a node refreshing its evidence rather
			// than provisioning new capacity).
			writeError(w, newError("no_tee_capacity",
				"no operator with current TEE attestation can serve this request"))
		case pick.StagingBlocked:
			// Operators advertise the model but every otherwise-fitting node is
			// flagged on-chain as `staging` and this proxy isn't configured to use
			// them. 503 (not 400): the request is well-formed; there's just no
			// production node for the model right now. Distinct code so the owner
			// sees the actionable hint rather than a generic no_operator.
			writeError(w, newError("no_production_operator",
				fmt.Sprintf("the model %q is only served by staging nodes; enable zs.allow_staging (or --allow-staging) to route to them", model)))
		case pick.SignerUnderfundedBlocked:
			// Every otherwise-eligible node (or the strict-affinity pin) has a
			// signing account too low to pay the fees of the open/settle it would
			// sign. 503: nothing is wrong with the request, and it clears on its
			// own when an operator tops up — unlike no_production_operator there is
			// no knob the payer can turn.
			msg := pick.SignerUnderfundedReason
			if msg == "" {
				msg = fmt.Sprintf("every node serving the model %q has less than %d ALGO spendable in its signing account to pay network fees; retry later or pick another model",
					model, selection.MinSignerSpendableMicroAlgos/1_000_000)
			}
			writeError(w, newError("no_funded_operator", msg))
		case pick.RegistryCount == 0:
			// Name the model — this is the most common 503 (a client like
			// Codex asking for a model id no operator in the pool serves), and
			// the model id is loggable/surfaceable (not prompt content), so
			// saying which one turns "no idea why" into a one-line diagnosis.
			writeError(w, newError("no_operator",
				fmt.Sprintf("no operator is currently advertising the model %q", model)))
		case pick.ImageEndpointUnsupported:
			// Operators advertise the model id but none publish the
			// matching image factor — typically a model that serves
			// edits only being requested for generation (or vice versa).
			// 503 no_operator because, from the client's perspective,
			// there is no operator serving this endpoint for this model
			// right now; a different endpoint or a different model may
			// succeed.
			var which string
			if endpoint == endpointImages {
				which = "image generation"
			} else {
				which = "image edits"
			}
			writeError(w, newError("no_operator",
				fmt.Sprintf("no operator advertises %s for %s", model, which)))
		case pick.AffinityBlocked:
			// Strict affinity pinned this conversation to a specific
			// operator that can no longer serve it (size, registry
			// expiry, or unknown previous_response_id). Other operators
			// may be willing and able, but relocating a tool-calling
			// conversation or Responses API session silently would
			// corrupt state — so we surface the real reason instead of
			// misrepresenting it as a pool-wide context_length_exceeded.
			//
			// AffinityBlockReason is set when the underlying cause isn't
			// "size doesn't fit" (e.g. previous_response_id miss).
			msg := pick.AffinityBlockReason
			if msg == "" {
				msg = fmt.Sprintf("strict affinity target cannot serve %s with input_tokens=%d max_output_tokens=%d; "+
					"reduce prompt size or switch affinity_policy to \"prefer\"",
					model, sizing.InputTokens, sizing.MaxOutputTokens)
			}
			writeError(w, newError("context_length_exceeded", msg))
		case pick.PinConflict:
			// A previous_response_id continuation resolves to an operator the
			// caller's hard preferences exclude — a client contradiction (serve
			// EITHER the continuation OR the pin, not both). 400: retrying the
			// same body can't resolve it; the client drops the pin or starts a
			// new conversation. Distinct from no_pinned_operator (availability).
			writeError(w, newError("pin_conflicts_with_continuation", pick.PinConflictReason))
		case pick.ProviderPinBlocked:
			// A caller routing preference (`provider.only`, or `provider.order`
			// with allow_fallbacks=false) matched no operator that can serve
			// this model right now. 503 (not 400): the request is well-formed —
			// a malformed ref is skipped at parse time and never reaches here —
			// so this is a pool-availability condition like no_operator /
			// no_tee_capacity, and a retry can succeed once the pinned
			// operator/node reappears. Distinct code so a client can tell "my
			// pin is unsatisfiable right now" from a generic pool outage.
			writeError(w, newError("no_pinned_operator",
				fmt.Sprintf("no operator matching your provider preferences is currently available "+
					"to serve %s; adjust provider.only / provider.order or remove the pin", model)))
		case pick.PriceBlocked:
			// A caller `max_price` ceiling excluded every otherwise-eligible
			// operator (operators with an undeclared rate count as too
			// expensive). 400, like OpenRouter's "no provider meets the
			// price cap" — the request can't execute as priced; the client
			// raises the ceiling or removes it.
			writeError(w, newError("price_ceiling_exceeded",
				fmt.Sprintf("no operator serves %s within your provider.max_price ceiling; "+
					"raise or remove the ceiling", model)))
		case pick.ToolUnsupported:
			// require_tools was set and no operator advertises every
			// requested zs_* tool. 503 (like no_tee_capacity): this is a
			// required-capability gap in the pool, not a malformed request —
			// a retry may succeed once a capable operator appears.
			writeError(w, newError("no_tool_capacity",
				fmt.Sprintf("no operator advertises every requested built-in tool for %s "+
					"(provider.require_tools is set)", model)))
		default:
			// Registry has operators for the model but none fits the
			// request size. This is a client-side problem (prompt too
			// big), not an availability problem — 400, not 503. The
			// per-operator breakdown turns "nobody fits" into a
			// directly actionable error: the client sees which limit
			// is being blown out and by how much for each candidate.
			writeError(w, newError("context_length_exceeded", formatNoFitMessage(model, sizing, pick.SizingMisses)))
		}
		return
	}
	candidates := pick.Operators

	var busyHint time.Duration
	// anyBusy records that SOME candidate answered 429, sticky across sweeps.
	// Deliberately separate from busyHint, which is only the largest Retry-After
	// seen: a 429 without that header is still a capacity answer, so busyHint == 0
	// does NOT mean "nobody was busy". Every terminal branch below that means to
	// ask "was anyone at capacity?" reads this; busyHint is only ever read for the
	// header value it names. Conflating the two meant a hint-less 429 alongside one
	// ephemeral-gapped candidate reported no_ephemeral_capacity — a hard posture
	// gap — when the truthful answer was that the pool was full.
	var anyBusy bool
	// Per-operator sizing rejections collected from the reserve loop.
	// The proxy pre-filter (Fits) already drops operators whose
	// *advertised* capacities don't fit, but operators can refuse on
	// stricter node-side limits the advertisement didn't expose — that
	// shows up here as an HTTP 400 context_length_exceeded. We capture
	// each one so that, if every surviving candidate refuses for sizing,
	// the client gets the actionable 400 with a per-operator breakdown
	// instead of a misleading 503 operators_busy.
	var reserveSizeRejections []reserveSizeRejection
	// relayUnavailable is set when transport-privacy mode is on but a
	// candidate has no eligible relay. We never silently fall back to a
	// direct route (that would void the privacy guarantee); the candidate is
	// skipped and, if every candidate is skipped for this reason, surfaced as
	// 503 no_relay_available after the loop.
	var relayUnavailable bool
	// toolFactorMissing is set when the client budgeted a hayai image tool
	// but a candidate's capacity entry for the requested chat model doesn't
	// publish the matching synthetic-token factor — so the proxy can't size
	// the budget against this operator and skips it like the image-route
	// branches do. NOTE: pickCandidates now *re-ranks* factor-capable operators
	// ahead via the in-loop image-tool partition (SelectTargets step 7b), but
	// that's a preference, not a filter — so a candidate still reaching this
	// branch is one that sank to the secondary partition because every
	// model-serving operator lacks the factor. Used as a last-resort signal:
	// when no operator was merely busy or relay-gapped, an all-skip outcome
	// becomes a 400 unsupported_tool after the loop (the model can't serve the
	// tool).
	var toolFactorMissing bool
	// ephemeralMissing is set when a candidate has no valid, unexpired signed
	// ephemeral recipient (Reserve returned errNoEphemeral). Under mandatory
	// forward secrecy there is no durable-key fallback, so the candidate is
	// skipped and, if every candidate is skipped for this reason — none merely
	// busy, size-rejected, or relay-gapped — surfaced as 503
	// no_ephemeral_capacity after the loop, mirroring no_tee_capacity.
	var ephemeralMissing bool
	// priceRejected is set when a candidate returned a validly-signed ticket
	// whose price failed payer-side verification (C1–C5). Skipped like a size
	// rejection; when every candidate is rejected this way — none merely busy or
	// relay-gapped — it surfaces as a terminal 502 after the loop.
	var priceRejected bool
	// Build the relay-candidate pool once for the whole reserve loop — it's
	// target-independent, so rebuilding it per candidate (the old relayHopFor)
	// was O(n)·candidates of wasted whole-fleet projection. nil when privacy is
	// off (relayHopForPool short-circuits before touching it).
	var relaySel []selection.Operator
	if usePrivacy {
		relaySel = s.relayPool(ctx)
	}
	// transientExhausted records that we gave up while every candidate was
	// failing with an infrastructure error rather than refusing the request.
	// It picks the terminal error below: "the pool is unreachable right now" is
	// both true and actionable, where the old operators_busy told the caller the
	// network was congested and invited an immediate retry storm.
	var transientExhausted bool
	// anyRefusal is sticky across sweeps: set the moment ANY candidate gives a
	// considered refusal that leaves no other durable record (a coded/default
	// non-retryable error, or a 429 whose Retry-After didn't raise busyHint). The
	// terminal operators_unreachable message asserts "none refused the request",
	// so it must NOT fire once one has — even if an EARLIER sweep was pure weather
	// and set transientExhausted. The size/price/ephemeral/relay/tool refusals
	// already have their own sticky accumulators + earlier terminal branches, so
	// they don't need to feed this; it exists for the two paths that didn't.
	var anyRefusal bool
	// Longest Retry-After any transient failure hinted this request. A gateway
	// that tells us when it will be back is better information than our fixed
	// table, so it paces the sweeps. Deliberately NOT busyHint: a busy operator
	// is a considered refusal that ends the sweeps outright, so busyHint is
	// always zero by the time a sweep runs and reading it here would be dead.
	var transientHint time.Duration
	// Whole-request retry budget, shared by the per-candidate rotation and the
	// sweeps below (transient.Wait stops both once it's spent).
	retryDeadline := time.Now().Add(s.transientRetryBudget())
	// Separate, much smaller budget for the busy re-sweep (see busyRetryBudget).
	// Deliberately NOT retryDeadline: waiting out a fleet restart is worth a
	// minute, waiting for a queue slot is worth seconds.
	busyDeadline := time.Now().Add(busyRetryBudget)
	busyRetriesLeft := busyRetries
	// Why the PREVIOUS pass asked for another one; picks this pass's wait + log.
	resweep := resweepNone
	// Outer sweep: re-walk the whole candidate list on a slow schedule when
	// EVERY candidate failed transiently. That is the fleet-restart signature —
	// a node update rolls through the network, every ingress answers 5xx for a
	// few seconds, and without this the caller eats a hard failure for a
	// condition that clears on its own. Bounded hard by retryDeadline, and
	// entered only from the guard at the bottom of the loop, which requires that
	// nothing gave a considered refusal (a size rejection, a price violation, a
	// busy signal) — those are answers, not weather, and re-asking won't change
	// them.
	for sweep := 0; sweep < transient.Sweeps; sweep++ {
		if sweep > 0 {
			// The wait comes from whichever condition earned this pass — the slow
			// transient table paced by a gateway's hint, or the short busy schedule
			// paced by the node's Retry-After against its own budget.
			var d time.Duration
			var ok bool
			if resweep == resweepBusy {
				d, ok = s.busyRetryWait(busyHint, time.Until(busyDeadline))
			} else {
				d, ok = transient.Wait(s.sweepDelay(sweep), transientHint, time.Until(retryDeadline))
			}
			if !ok || !sleepCtx(ctx, d) {
				break
			}
			// Re-resolve candidates: a node that finished restarting is eligible
			// again, and pickCandidates re-applies the freshest reachability. An
			// error here just ends the sweeps with whatever we already know.
			repick, err := s.pickCandidates(ctx, endpoint, model, body, sizing, requireTEE, toolBudgets, routingPrefs)
			if err != nil || len(repick.Operators) == 0 {
				break
			}
			candidates = repick.Operators
			// Re-project the relay pool too. relayPool is this path's only reader
			// of RelayDownranked (the discovery buildSelAll is the other one, on
			// its own cadence), so without this a relay that this very request
			// just proved dead — by rotation differential, or by answering a
			// code-less 5xx without a hop marker — keeps its snapshotted
			// preferred-tier standing and is re-drawn at full weight for the
			// remaining sweeps, up to another 46s of dialing a corpse. That was
			// tolerable while the dispatch path recorded nothing; now that it
			// does, the pool has to see it. Mirrors the candidate re-resolve
			// above, and costs one whole-fleet projection against a 4-30s wait.
			if usePrivacy {
				relaySel = s.relayPool(ctx)
			}
			if resweep == resweepBusy {
				s.log.Info("every operator was at capacity; re-sweeping after the hinted wait",
					slog.String("endpoint", endpoint),
					slog.String("model", model),
					slog.Int("sweep", sweep+1),
					slog.Int("candidates", len(candidates)),
					slog.Duration("waited", d))
			} else {
				s.log.Info("every operator failed transiently; re-sweeping the candidate list",
					slog.String("endpoint", endpoint),
					slog.String("model", model),
					slog.Int("sweep", sweep+1),
					slog.Int("candidates", len(candidates)))
			}
		}
		// Per-sweep outcome tally. A sweep may repeat when it was pure weather
		// (sweepTransient with no refusal at all), or when it was pure capacity
		// (sweepBusy with no OTHER refusal) — the two are tracked apart because
		// they earn different budgets. sweepRefused keeps its original meaning,
		// "some candidate gave a considered refusal", and so still covers busy:
		// the terminal operators_unreachable message asserts none refused, and a
		// 429 is a refusal. sweepHardRefusal is the narrower "refused for a reason
		// waiting cannot fix", which is what disqualifies a busy re-sweep.
		sweepTransient, sweepRefused := false, false
		sweepBusy, sweepHardRefusal := false, false
		for _, op := range candidates {
			// Transport-privacy: pick the relay hop for this target. nil hop =
			// privacy off (direct send); ErrNoRelay = privacy on but no eligible
			// relay → skip this candidate, never route direct.
			hop, relayErr := s.relayHopForPool(relaySel, op, usePrivacy)
			if relayErr != nil {
				relayUnavailable = true
				s.log.Info("privacy mode: no eligible relay; skipping operator",
					opAttr(op),
					slog.String("endpoint", endpoint))
				if s.cfg.Affinity == hayai.AffinityStrict {
					break
				}
				continue
			}
			// Per-operator max_output: the flat estimate when the caller specified one
			// (or a per-model default applied), else the derivation from THIS
			// operator's declared capacity — the identical value the sizing filter
			// admitted this operator on (hayai.Fits ↔ selection.effectiveMaxOutput).
			opMaxOutput := hayai.EffectiveMaxOutput(op, sizing)
			inputCount, boundVersion := reserveInputCount(op, model, body, opMaxOutput)
			reserveReq := ticket.ReserveRequest{
				Model:          model,
				InputCount:     inputCount,
				MaxOutputCount: opMaxOutput,
				Stream:         wantsStream,
				PayerAddr:      s.wallet.PayerAddr(),
				// Tell the node which bound sized InputCount so it re-measures the
				// decrypted body with the same function. Omitted (0 ⇒ v1) for a
				// pre-9.2 target, which wouldn't understand the field anyway.
				InputBoundVersion: boundVersion,
			}
			if isImage {
				// Per-operator dedicated-route sizing. The NODE sizes the reserve
				// as imageprice.CostMicroUSDC(rate, n, size, quality) from the request
				// params we forward here. The synthetic-token factor basis is retired
				// — the microUSDC rate is the only basis. Exact; refund variance is
				// near zero by design.
				cap := op.ModelCapacities[model]
				if !cap.ServesImageGen() {
					// Defensive fallback: pickCandidates already drops operators
					// that don't serve the gen endpoint. Debug, not Warn — the
					// symmetric "edit-only model" advertisement is legitimate.
					s.log.Debug("operator does not serve image generation at reserve time; skipping",
						opAttr(op),
						relayAttr(hop),
						slog.String("model", model))
					continue
				}
				reserveReq.InputCount = 0
				reserveReq.MaxOutputCount = 0
				reserveReq.ImageN = uint64(imageN)
				reserveReq.ImageSize = imageSize
				reserveReq.ImageQuality = imageQuality
			}
			if isImageEdit {
				// Same shape as isImage but the edit route (image_edit_rate). We
				// skip any operator that doesn't serve edits for this model.
				cap := op.ModelCapacities[model]
				if !cap.ServesImageEdit() {
					s.log.Debug("operator does not serve image edits at reserve time; skipping",
						opAttr(op),
						relayAttr(hop),
						slog.String("model", model))
					continue
				}
				reserveReq.InputCount = 0
				reserveReq.MaxOutputCount = 0
				reserveReq.ImageN = uint64(imageN)
				reserveReq.ImageSize = imageSize
				reserveReq.ImageQuality = imageQuality
				reserveReq.ImageEdit = true
			}
			if !isImage && !isImageEdit && (toolBudgets.GenerationMaxN > 0 || toolBudgets.EditMaxN > 0) {
				// Carry the client's image-tool budget on the chat reserve.
				// The per-tool microUSDC cap lives on the OUTER chat model's
				// ImageToolRateMicroUSDC / ImageEditToolRateMicroUSDC (NOT the
				// dedicated ImageRateMicroUSDC, which is the "serves /v1/images/*"
				// signal and is zero on a chat model). A candidate whose capacity
				// for this model doesn't publish a tool rate can't size it
				// (RequestedTools only re-ranks, it doesn't filter, so a candidate
				// here may not offer the tool at all); skip it and remember why, so
				// an all-skip outcome — when no operator was merely busy or
				// relay-gapped — becomes a 400 unsupported_tool rather than a
				// misleading 503. Nothing is folded into MaxOutputTokens: the node
				// adds max_n × cap to MaxPrice additively from the budget counts.
				mc := op.ModelCapacities[model]
				if toolBudgets.GenerationMaxN > 0 && mc.ImageToolRateMicroUSDC == 0 {
					toolFactorMissing = true
					s.log.Debug("operator missing image-tool pricing for chat-model image tool; skipping",
						opAttr(op), relayAttr(hop), slog.String("model", model))
					if s.cfg.Affinity == hayai.AffinityStrict {
						break
					}
					continue
				}
				if toolBudgets.EditMaxN > 0 && mc.ImageEditToolRateMicroUSDC == 0 {
					toolFactorMissing = true
					s.log.Debug("operator missing image-edit-tool pricing for chat-model image tool; skipping",
						opAttr(op), relayAttr(hop), slog.String("model", model))
					if s.cfg.Affinity == hayai.AffinityStrict {
						break
					}
					continue
				}
				reserveReq.ImageToolBudget = toolBudgets.GenerationMaxN
				reserveReq.ImageEditToolBudget = toolBudgets.EditMaxN
			}
			// Reserve rides the same relay hop, immediately before the inference
			// forward through it, so the leg is asymmetric on purpose: it never
			// CREDITS a relay — a reserve success would clear (delete) the streak
			// the imminent inference forward is the authoritative signal for,
			// letting a relay that forwards reserves but drops inference reset
			// itself every request and never downrank — but it DOES record a
			// proven fault (a transport failure to the relay's own socket, an
			// unmarked front-door status from a >=9.1 relay, or a rotation
			// differential). See transient_retry.go's header for why withholding
			// those was worse than the credit ever was.
			// One candidate's reserve leg, including the bounded transient retry
			// (rotating the relay each attempt) and the stale-ephemeral self-heal.
			// Both `op` and `hop` can be REPLACED by that call — a re-probe refreshes
			// the operator's ephemeral recipient, a rotation picks a different relay —
			// and the inference forward below must use the replacements, or it would
			// seal to a stale key or ship through the relay we just abandoned.
			// Re-size on a re-probe: the bound version and max_output are
			// per-operator, and a re-probe is the one point where the target's
			// advertised version can change under us. Nil on the dedicated image
			// routes, which size max_price from imageprice rather than the token
			// bound and deliberately carry input_count = 0.
			var resize func(hayai.Operator, *ticket.ReserveRequest)
			if !isImage && !isImageEdit {
				resize = func(o hayai.Operator, r *ticket.ReserveRequest) {
					maxOut := hayai.EffectiveMaxOutput(o, sizing)
					r.MaxOutputCount = maxOut
					r.InputCount, r.InputBoundVersion = reserveInputCount(o, model, body, maxOut)
				}
			}
			attempt := s.reserveWithTransientRetry(ctx, op, reserveReq, hop, relaySel, usePrivacy, retryDeadline, resize)
			op, hop = attempt.Op, attempt.Hop
			rt, err := attempt.Ticket, attempt.Err
			// Bound once, outside the switch, so the case body works with a value the
			// compiler knows is non-nil rather than re-deriving it with a discarded
			// errors.As bool.
			payerRefusal, isPayerRefusal := hayai.AsPayerRefusal(err)
			switch {
			case err == nil:
				// This node served us — clear any dispatch-failure window so it
				// returns to the preferred tier immediately rather than serving out
				// a backoff it has just disproved.
				if s.targetBackoff != nil {
					s.targetBackoff.RecordTargetOutcome(hayai.RefOf(op), true)
				}
				// The reserve is a small, pre-inference round-trip — a clean network-RTT
				// sample for the path it rode. Feed it to the latency store (separate
				// from the reputation streak this leg deliberately leaves unattributed,
				// per the comment above — latency is a distinct signal). Success-only,
				// and timed for the SUCCEEDING attempt alone: a retry's wall clock
				// includes the backoff sleep and the round-trips to whichever relays
				// failed first, none of which describe the path we actually took.
				if s.relayLatency != nil {
					d := attempt.Elapsed
					if hop != nil {
						s.relayLatency.RecordRelayedRTT(hop.RelayRef(), hop.TargetRef(), d)
					} else {
						s.relayLatency.RecordDirectRTT(hayai.RefOf(op), d)
					}
				}
				// Payer-side price gate: refuse a mis-priced or internally-inconsistent
				// ticket before opening escrow against it. A violation isn't retryable
				// against this operator, but another may be honest — skip it like a size
				// rejection (strict affinity stops instead of relocating). Fails open when
				// a reference is unavailable (see verifyReservePrice).
				if v := s.verifyReservePrice(op, reserveReq, rt.Ticket); v != nil {
					priceRejected = true
					s.log.Warn("reserve refused: ticket price failed verification; trying next operator",
						opAttr(op),
						relayAttr(hop),
						slog.String("check", v.Check),
						slog.String("field", v.Field),
						slog.Uint64("allowed", v.Want),
						slog.Uint64("signed", v.Got))
					if s.cfg.Affinity == hayai.AffinityStrict {
						break
					}
					continue
				}
				if s.log.Enabled(ctx, slog.LevelDebug) {
					t := rt.Ticket
					attrs := []slog.Attr{
						opAttr(op),
						relayAttr(hop),
						slog.String("ticket_id", t.TicketID),
						slog.String("model", t.Model),
						slog.Uint64("input_tokens", t.InputCount),
						slog.Uint64("max_output_tokens", t.MaxOutputCount),
						slog.Uint64("input_rate_microusdc_per_1m", t.InputRate),
						slog.Uint64("output_rate_microusdc_per_1m", t.OutputRate),
						slog.Uint64("cache_read_rate_microusdc_per_1m", t.CacheReadRate),
						slog.Uint64("max_price_microusdc", t.MaxPrice),
						slog.Bool("stream", t.Stream),
						slog.Time("expires_at", time.Unix(t.ExpiresAt, 0)),
					}
					// MaxPrice is microUSDC, so its USD value is independent of
					// the ALGO/USD oracle. The oracle reading still gets
					// surfaced because it's needed for ALGO network-fee USD
					// conversion further along the pipeline.
					attrs = append(attrs,
						slog.String("max_price_usd", fmt.Sprintf("$%.6f", float64(t.MaxPrice)/1_000_000)),
					)
					if rt.AlgoUSDPrice > 0 {
						attrs = append(attrs, slog.Float64("algo_usd", rt.AlgoUSDPrice))
					}
					s.log.LogAttrs(ctx, slog.LevelDebug, "reserve response", attrs...)
				}
				s.runHayaiSealed(w, r, endpoint, model, body, op, rt, wantsStream, hop, format)
				return
			case hayai.IsBusy(err):
				// A considered refusal, so it ends the sweeps — tracked separately
				// from busyHint because a 429 without a Retry-After header leaves
				// that at zero while still being an answer, not weather.
				sweepRefused = true
				anyBusy = true
				var be *hayai.BusyError
				if !errors.As(err, &be) {
					// hayai.IsBusy matched, so this cannot happen; keep the loop
					// safe rather than dereferencing a nil below.
					break
				}
				if be.RetryAfter > busyHint {
					busyHint = be.RetryAfter
				}
				// Gate on the code, never the bare 429: re-asking a payer_slot_cap
				// spends a penalty strike per ask. transient.RetryableBusyCode has
				// the full set.
				if be.Retryable() {
					sweepBusy = true
				}
				s.log.Info("operator busy; trying next",
					opAttr(op),
					relayAttr(hop),
					slog.String("endpoint", endpoint),
					slog.String("code", be.Code),
					slog.Bool("resweepable", be.Retryable()),
					slog.Duration("retry_after", be.RetryAfter))
				if s.cfg.Affinity == hayai.AffinityStrict {
					// Strict affinity: don't fall through to other operators.
					break
				}
			case hayai.IsSize(err):
				// Node refused on a node-side capacity limit the advertised
				// metadata didn't expose. Not retryable against the same
				// operator — but other operators may have larger limits, so
				// we keep iterating. Logged at Info because it's a client
				// request shape problem, not operator misbehaviour.
				var se *hayai.SizeError
				_ = errors.As(err, &se)
				reserveSizeRejections = append(reserveSizeRejections, reserveSizeRejection{
					OperatorID: op.ID,
					Code:       se.Code,
					Message:    se.Message,
				})
				s.log.Info("operator refused for sizing; trying next",
					opAttr(op),
					relayAttr(hop),
					slog.String("endpoint", endpoint),
					slog.String("code", se.Code))
				if s.cfg.Affinity == hayai.AffinityStrict {
					// Strict affinity: same logic as busy — don't relocate.
					break
				}
			case isPayerRefusal:
				// Payer-scoped refusal: the escrow contract said no about THIS
				// PAYER, not this operator. Every remaining candidate would refuse
				// the identical request identically, so stop the loop outright —
				// unlike every other case here, iterating is not just wasteful, it
				// actively misreports the condition as congestion. Surface the
				// node's own code/message: it names the real limit and when it
				// resets, which "all eligible operators are at capacity" does not.
				s.log.Info("payer-scoped refusal; not trying other operators",
					opAttr(op),
					relayAttr(hop),
					slog.String("endpoint", endpoint),
					slog.String("code", payerRefusal.Code))
				// Kind is set here, not looked up: a code added to
				// payerRefusalCodes without an errorShapes entry still renders
				// as a payer refusal.
				e := &hayai.Error{Kind: hayai.KindFunds, Code: payerRefusal.Code, Message: payerRefusal.Message, RetryAfter: payerRefusal.RetryAfter}
				writeError(w, e)
				return
			case hayai.IsNoEphemeral(err):
				// This operator has no valid, unexpired forward-secrecy ephemeral
				// recipient — Reserve refused to seal (mandatory forward secrecy, no
				// durable-key fallback). Skip the candidate (NOT a transport failure)
				// and remember why so an all-skip outcome becomes 503
				// no_ephemeral_capacity. Debug, not Warn: a node whose ephemeral
				// briefly lapsed (rotation gap) or hasn't been re-probed will trip
				// this routinely, and it's a posture outcome, not operator
				// misbehaviour. No key bytes logged — operator_id + relay only.
				ephemeralMissing = true
				s.log.Debug("operator has no valid ephemeral recipient; skipping",
					opAttr(op),
					relayAttr(hop),
					slog.String("endpoint", endpoint))
				if s.cfg.Affinity == hayai.AffinityStrict {
					// Strict affinity: don't relocate, same as the other skip cases.
					break
				}
			default:
				// Split the old catch-all in two. An infrastructure failure (a
				// gateway 5xx with no protocol error code, or a transport error) has
				// already burned its per-candidate rotation inside
				// reserveWithTransientRetry, so reaching here means that budget is
				// spent — but it is still weather, not an answer, so it keeps the
				// outer sweep eligible. Anything else is a genuine refusal by this
				// operator and ends the sweeps.
				if v, hint := classifyReserveErr(ctx, err, hop); v.Retryable {
					sweepTransient = true
					if hint > transientHint {
						transientHint = hint
					}
					// Record a target strike ONLY for a failure this node is
					// answerable for. A relay-side fault (AttrRelay) belongs to
					// relay reputation. An unattributable gateway error
					// (AttrUnknown) belongs to nobody WHEN A RELAY IS IN THE PATH —
					// benching a healthy node for someone else's broken CDN is the
					// exact misattribution this work set out to fix, and during a
					// fleet-wide restart it would bench most of the pool at once.
					// But in DIRECT mode there is no relay, so a code-less 5xx /
					// transport failure IS this node's own ingress — strike it,
					// exactly as the client does (its isRelayAttributable
					// short-circuits `!isPrivacyEnabled()`). Without this branch the
					// proxy and client diverge and a sick direct-mode node is never
					// demoted.
					//
					// The verdict arrives already narrowed by the route evidence
					// (classifyReserveErr → transient.NarrowRelayed), so the
					// AttrUnknown that reaches here is the genuinely undecidable
					// residue — a code-less status from a pre-9.1 relay — rather
					// than merely an uninspected one. A relayed failure the marker
					// resolved onto the target arrives as AttrTarget and DOES strike,
					// through the same path a relay_upstream_unreachable claim
					// already took.
					if s.targetBackoff != nil && shouldRecordTargetFailure(v, usePrivacy) {
						s.targetBackoff.RecordTargetOutcome(hayai.RefOf(op), false)
					}
					s.log.Warn("operator unreachable through infrastructure; trying next operator",
						opAttr(op),
						relayAttr(hop),
						slog.String("endpoint", endpoint),
						slog.String("attribution", string(v.Attribution)),
						slog.Any("err", err))
				} else {
					sweepRefused = true
					// An uncategorized reserve failure is not capacity, so it
					// disqualifies a busy re-sweep even if another candidate was busy.
					sweepHardRefusal = true
					s.log.Warn("reserve failed; trying next operator",
						opAttr(op),
						relayAttr(hop),
						slog.String("endpoint", endpoint),
						slog.Any("err", err))
				}
			}
		}

		// Any considered refusal this sweep is sticky evidence for the terminal
		// selection below — a busy/coded refusal in sweep 1 must override a
		// transientExhausted set in sweep 0, or we'd report operators_unreachable
		// ("none refused the request") when one just did.
		if sweepRefused {
			anyRefusal = true
		}
		// Two independent reasons to sweep again, each with its own budget and its
		// own disqualifier set.
		//
		// weatherBlocked is the ORIGINAL guard, term for term — a size rejection, a
		// price violation, a relay gap, a missing ephemeral, an uncategorized
		// reserve failure, or any busy signal. Each is a property of the request or
		// the fleet that waiting doesn't change. The existing accumulators double as
		// the record, so those paths vote here without extra bookkeeping.
		weatherBlocked := sweepHardRefusal ||
			len(reserveSizeRejections) > 0 || anyBusy ||
			relayUnavailable || toolFactorMissing || ephemeralMissing || priceRejected
		// busyBlocked is deliberately NARROWER, and matches the terminal ladder
		// below: only the branches that outrank busy there may veto a busy
		// re-sweep. `reserveSizeRejections` (the 400) and `relayUnavailable` have no
		// busy gate, so they win over busy and must stop the re-sweep.
		// `toolFactorMissing`, `ephemeralMissing` and `priceRejected` ARE gated on
		// `!anyBusy`, i.e. the ladder already treats them as subordinate to busy —
		// so letting them veto here would contradict it. That mattered in practice:
		// `ephemeralMissing`'s own comment notes a node trips it routinely on a
		// rotation gap, so one such candidate in a heterogeneous fleet would have
		// disabled the re-sweep for the whole request. (Those gates read `anyBusy`,
		// not `busyHint > 0`, precisely so this correspondence holds for a 429 that
		// carried no Retry-After — otherwise the re-sweep would engage and the
		// ladder would then contradict it.)
		busyBlocked := sweepHardRefusal ||
			len(reserveSizeRejections) > 0 || relayUnavailable
		switch {
		case sweepTransient && !sweepRefused && !weatherBlocked:
			// Pure weather: every candidate failed transiently and nothing refused.
			// Ride out the fleet restart on the slow schedule.
			transientExhausted = true
			resweep = resweepWeather
		case sweepBusy && !busyBlocked && busyRetriesLeft > 0 && time.Now().Before(busyDeadline):
			// Pure capacity: at least one candidate was at capacity, none refused for
			// a reason waiting can't fix. Come back after the hinted wait — a slot
			// frees the moment an in-flight ticket settles. Deliberately does NOT set
			// transientExhausted: the pool is reachable, it is full, and the terminal
			// error must stay operators_busy (with its Retry-After) rather than
			// claiming the pool is unreachable.
			busyRetriesLeft--
			resweep = resweepBusy
		default:
			resweep = resweepNone
		}
		if resweep == resweepNone {
			break
		}
	}

	// Everybody said no. Prefer the actionable 400 over the generic
	// 503: a sizing rejection is a hard client-side problem (the
	// request as shaped will not succeed against any of these operators
	// no matter how long the client waits), so when at least one
	// operator refused for sizing — at reserve time OR pre-filter — we
	// surface that. Folding pre-filter SizingMisses in here is what
	// keeps the diagnostic visible when a *separate* candidate (e.g. a
	// reachable wildcard operator that doesn't actually serve the
	// model) survives pickCandidates and then fails at reserve for an
	// unrelated reason like a timeout. Pure-busy outcomes (or strict
	// affinity with a busy operator) keep returning 503 + Retry-After
	// unchanged.
	if len(reserveSizeRejections) > 0 || len(pick.SizingMisses) > 0 {
		writeError(w, newError("context_length_exceeded",
			formatReserveSizeFailureMessage(model, sizing, reserveSizeRejections, pick.SizingMisses)))
		return
	}
	// The client budgeted a hayai image tool but no candidate could
	// size it — every operator's capacity for the requested chat model lacks
	// the synthetic-token factor — AND no operator was merely busy or relay-
	// gapped. That makes it a hard client-side problem (a retry won't help):
	// a 400 distinct from context_length_exceeded so the client can tell
	// "model can't do this" from "prompt too big". The anyBusy /
	// relayUnavailable guard is load-bearing: an operator only reaches the
	// reserve (and so only reports busy) AFTER passing the factor gate, so a
	// busy operator proves the tool IS serviceable — surfacing this terminal
	// 400 ahead of the retryable 503 would wrongly tell the client to give
	// up. Those retryable outcomes win below.
	if toolFactorMissing && !anyBusy && !relayUnavailable {
		writeError(w, newError("unsupported_tool",
			fmt.Sprintf("no operator serves a built-in image tool for model %s — the model does not advertise an image-tool factor", model)))
		return
	}
	// Transport-privacy mode with no eligible relay for any candidate. A
	// distinct 503 (not operators_busy) so the client/operator can tell a
	// privacy-fleet gap (too few operators, or all share the target's owner)
	// from genuine capacity exhaustion. We never route direct to recover.
	if relayUnavailable {
		writeError(w, newError("no_relay_available",
			"transport-privacy mode is enabled but no eligible relay operator is available for the selected target(s)"))
		return
	}
	// Fail-closed forward secrecy: every candidate
	// was skipped because none has a valid, unexpired ephemeral recipient — and
	// no operator was merely busy or relay-gapped (size rejections already
	// returned a 400 above). A distinct 503 (not operators_busy) so the client
	// can tell a forward-secrecy posture gap from genuine capacity exhaustion;
	// mirrors no_tee_capacity. There is no durable-key fallback.
	if ephemeralMissing && !anyBusy && !relayUnavailable {
		writeError(w, newError("no_ephemeral_capacity",
			"no operator with a valid forward-secrecy ephemeral recipient can serve this request"))
		return
	}
	// Every eligible operator returned a ticket whose price failed verification —
	// and none was merely busy or relay-gapped, so a retry won't help. Operator-
	// side misbehaviour (a mis-priced or internally-inconsistent ticket), so a 502
	// distinct from operators_busy. Ranks below the retryable busy/relay outcomes.
	if priceRejected && !anyBusy && !relayUnavailable {
		writeError(w, newError("ticket_price_rejected",
			"every eligible operator returned a ticket whose price failed verification (mis-priced or internally inconsistent)"))
		return
	}
	// Every candidate was unreachable through infrastructure — a gateway 5xx
	// with no protocol error code, or a transport failure — and the whole
	// rotation + sweep budget is spent without any operator ever refusing the
	// request. This is the fleet-restart signature, and calling it operators_busy
	// was actively misleading: the pool is not at capacity, it is unreachable,
	// and "retry after the hint" invited a retry storm at exactly the wrong
	// moment. A distinct code lets a client back off on the right cadence.
	if transientExhausted && !anyRefusal && !anyBusy && !relayUnavailable {
		e := newError("operators_unreachable",
			fmt.Sprintf("every operator serving %s is currently unreachable through its gateway, "+
				"and none refused the request; this usually clears within a minute — retry after the hint", model))
		e.RetryAfter = transientRetryAfterHint
		writeError(w, e)
		return
	}
	e := newError("operators_busy", "all eligible operators are at capacity; retry after the hint")
	e.RetryAfter = busyHint
	writeError(w, e)
}

// transientRetryAfterHint is the Retry-After we give a client when the whole
// pool was unreachable through infrastructure. Deliberately longer than the
// retry budget we just spent: we already rotated relays and re-swept the list
// for a minute, so an immediate retry would re-run that same doomed minute. It
// is sized to land on the far side of a typical node restart instead.
const transientRetryAfterHint = 30 * time.Second

// Busy re-sweep pacing. A 429 from every candidate is the one considered
// refusal worth re-asking, because capacity is the only one that is
// TIME-VARYING and self-announcing: the node hands us a Retry-After, and an
// in-flight ticket completing frees a slot, so the same question genuinely gets
// a different answer seconds later. Every other refusal in the sweep guard —
// a size rejection, a price violation, a missing ephemeral, a relay gap — is a
// property of the request or the fleet that waiting cannot change.
//
// Kept proxy-local rather than in proto/go/transient on purpose: that package is
// golden-vectored and mirrored in proto/ts, so a schedule living there is a
// cross-repo publish + pin bump. Move it there if client/ adopts the same
// behavior and the two need to be provably identical.
const (
	// busyRetries is how many extra passes over the candidate list a pure-busy
	// sweep earns, beyond the first. Bounded independently of transient.Sweeps
	// (which the loop still caps against) because the two budgets answer
	// different questions.
	busyRetries = 2

	// busyRetryBudget bounds when a busy re-sweep may still be STARTED, measured
	// from dispatch entry — not the extra time it adds. Two consequences worth
	// knowing: a pass that begins just inside the deadline runs to completion
	// beyond it (so worst-case added wall clock is the sleeps plus up to
	// busyRetries full candidate passes), and on a pool slow enough that sweep 0
	// alone spends the budget the re-sweep never engages at all.
	//
	// Sized for an interactive caller: an IDE that fans out a dozen concurrent
	// requests at a three-node pool needs a few seconds of queueing, NOT the
	// 60s transient.OverallDeadline spent riding out a fleet restart. A caller
	// that waited that long would have timed out on its own.
	busyRetryBudget = 8 * time.Second

	// busyRetryDelay is the fallback wait when a 429 carried no Retry-After.
	busyRetryDelay = 1 * time.Second

	// busyRetryMaxDelay clamps the hinted wait so one operator's hostile or
	// mis-set Retry-After can't spend the whole budget by itself.
	busyRetryMaxDelay = 3 * time.Second
)

// resweepReason records WHY the previous pass asked for another one, so the top
// of the loop can pick the matching wait and log line. The two reasons have
// different budgets and different meanings and must not share a schedule.
type resweepReason int

const (
	resweepNone resweepReason = iota
	resweepWeather
	resweepBusy
)

// busyRetryWait resolves the wait before a busy re-sweep. The operator's own
// hint wins when longer (clamped), and remaining is the busy budget rather than
// the transient one. s.fastSweeps zeroes it so a test can drive the busy
// re-sweep path without real waits — it has to zero the HINT too, since
// transient.Wait lets a server-supplied Retry-After beat the scheduled value.
func (s *Server) busyRetryWait(hint, remaining time.Duration) (time.Duration, bool) {
	if s.fastSweeps {
		if remaining <= 0 {
			return 0, false
		}
		return 0, true
	}
	if hint > busyRetryMaxDelay {
		hint = busyRetryMaxDelay
	}
	return transient.Wait(busyRetryDelay, hint, remaining)
}

// reserveSizeRejection captures a single operator's node-side sizing
// refusal during the reserve loop. Code mirrors the OpenAI-shaped
// `error.code` from the node (today only "context_length_exceeded");
// Message mirrors `error.message` so the proxy can surface the
// underlying reason verbatim instead of paraphrasing it.
type reserveSizeRejection struct {
	OperatorID uint64
	Code       string
	Message    string
}

// formatReserveSizeFailureMessage builds the body for the 400 returned
// when at least one operator refused for size — either at reserve time
// (rejections, populated by the dispatch loop on a node-side
// context_length_exceeded) or at the proxy's pre-filter (preFilter,
// populated by pickCandidates). Mirrors formatNoFitMessage's shape so
// clients that key off the header line ("no operator serves <model>
// with input_tokens=...") see the same wording whether the rejection
// happened at the proxy pre-filter or at the node's reserve handler.
// The per-operator lines use the node's own message (for reserve-time
// rejections) or the pre-filter capacity envelope (for pre-filter
// rejections) so the client sees the exact ceiling that blew out, not
// a paraphrase.
func formatReserveSizeFailureMessage(model string, sizing hayai.SizingRequest, rejections []reserveSizeRejection, preFilter []sizingMiss) string {
	head := fmt.Sprintf("no operator serves %s with input_tokens=%d max_output_tokens=%s",
		model, sizing.InputTokens, noFitMaxOutputLabel(sizing))
	if len(rejections) == 0 && len(preFilter) == 0 {
		return head
	}
	var b strings.Builder
	b.WriteString(head)
	if len(rejections) > 0 {
		b.WriteString("\n  operators rejected the request at reserve time:")
		for _, r := range rejections {
			b.WriteString("\n  - ")
			b.WriteString(describeReserveSizeRejection(r))
		}
	}
	if len(preFilter) > 0 {
		b.WriteString("\n  operators advertising this model:")
		for _, m := range preFilter {
			b.WriteString("\n  - ")
			b.WriteString(describeMiss(m, sizing))
		}
	}
	return b.String()
}

// describeReserveSizeRejection formats a single operator's reserve-time
// sizing rejection. Falls back to the bare code if the node didn't
// include a message (older nodes / unusual paths) — never returns an
// empty string so the per-operator breakdown stays useful.
func describeReserveSizeRejection(r reserveSizeRejection) string {
	if r.Message != "" {
		return fmt.Sprintf("op %d: %s (%s)", r.OperatorID, r.Message, r.Code)
	}
	if r.Code != "" {
		return fmt.Sprintf("op %d: %s", r.OperatorID, r.Code)
	}
	return fmt.Sprintf("op %d: refused for size (no detail)", r.OperatorID)
}

// pickResult is what dispatchHayai needs to choose the right HTTP status
// when the candidate list is empty:
//
//   - RegistryCount == 0         → nobody advertises this model (503 no_operator)
//   - AffinityBlocked            → strict affinity pinned us to an operator
//     that cannot serve this request; other operators may be able, but
//     we won't silently relocate a tool-calling conversation or a
//     previous_response_id continuation (400 with a distinct message).
//     When AffinityBlockReason is set, dispatchHayai uses it verbatim
//     as the client-facing message — used by previous_response_id pins
//     where the failure mode is not a context-window mismatch.
//   - otherwise (empty Operators) → the sizing filter dropped every operator
//     (400 context_length_exceeded, pool-wide). SizingMisses carries each
//     dropped operator's declared envelope so the error body can spell out
//     why every candidate was filtered — turning a generic
//     "no operator serves" into actionable diagnostics.
type pickResult struct {
	Operators           []hayai.Operator
	RegistryCount       int
	AffinityBlocked     bool
	AffinityBlockReason string
	SizingMisses        []sizingMiss

	// TEEBlocked is set when the request required TEE
	// (X-Zs-Require-TEE header or
	// zs.tee.require_for_models match) and every otherwise-fitting
	// operator failed the IsTEEAttested filter. dispatchHayai
	// translates this into 503 no_tee_capacity rather than the
	// generic no_operator / context_length_exceeded paths — silent
	// fallback to a non-attested operator would defeat the entire
	// confidential-mode contract.
	TEEBlocked bool

	// StagingBlocked is set when operators advertise the model but every
	// otherwise-fitting node is flagged on-chain as `staging` and the request
	// did not opt in (zs.allow_staging / --allow-staging /
	// PROXY_ZS_ALLOW_STAGING). Surfaced as 503 no_production_operator with a
	// hint to enable staging — distinct from RegistryCount==0 so "the model is
	// served, just only on staging nodes" is actionable rather than looking like
	// nobody serves it.
	StagingBlocked bool

	// SignerUnderfundedBlocked is set when every otherwise-eligible node has a
	// signing account known to hold less than
	// selection.MinSignerSpendableMicroAlgos spendable, or when an affinity pin
	// (strict tool-call, or previous_response_id) lands on such a node. Surfaced
	// as 503 no_funded_operator.
	SignerUnderfundedBlocked bool
	// SignerUnderfundedReason, when set, replaces the model-wide 503 message:
	// a pin to one drained node says nothing about the model's other nodes,
	// and "pick another model" would abandon the session for no reason.
	SignerUnderfundedReason string

	// VersionBlocked is set when the registry has otherwise-fitting
	// operators for this model but none of them advertise a
	// wire-protocol major matching wire.ProtoVersion. Surfaced as 503
	// no_compatible_operator. Distinct from RegistryCount==0
	// (nobody serves this model) and TEEBlocked (attestation gap):
	// here, capacity exists but every candidate speaks a wire
	// generation this proxy build cannot interop with, so a retry on
	// the same fleet will keep failing until the fleet upgrades or
	// the proxy/client downgrades — clients should treat the failure
	// as load-bearing diagnostic ("upgrade required"), not a
	// transient pool problem.
	VersionBlocked bool

	// ImageEndpointUnsupported is set when the requested endpoint is
	// /v1/images/generations or /v1/images/edits, the registry has
	// operators advertising the model id, but none of them serve the
	// matching per-endpoint route (ServesImageGen for generation,
	// ServesImageEdit for edits). That signal is the only one the proxy
	// has for sizing the reserve, so a missing one means the operator does
	// not serve this endpoint for this model — symmetric "gen-only" or
	// "edit-only" advertisements are legitimate, not misconfigured.
	// Distinct from RegistryCount==0 so the client can tell "no one
	// serves this model at all" from "no one serves this model on
	// this endpoint"; surfaced as 503 no_operator with an endpoint-
	// specific message.
	ImageEndpointUnsupported bool

	// ProviderPinBlocked is set when a caller routing preference (the
	// `provider` object) matched no operator that could serve the request:
	// an `only` allowlist that excluded every model-serving operator, or an
	// `order` with allow_fallbacks=false whose refs matched no eligible
	// candidate. Surfaced as 503 no_pinned_operator — like no_operator /
	// no_tee_capacity / no_compatible_operator, this is a pool-availability
	// condition (the pin is well-formed; nothing matches it right now), so a
	// retry can succeed once the pinned operator/node reappears. NOT 400: a
	// malformed ref is skipped at parse time and never reaches here, so the
	// request itself is valid.
	ProviderPinBlocked bool

	// PinConflict is set when a previous_response_id continuation resolves to a
	// specific operator that the caller's hard preferences (only / ignore /
	// no-fallback order) exclude — two mutually exclusive demands. Unlike
	// ProviderPinBlocked this is a genuine client contradiction (retrying the
	// same body never helps), surfaced as 400 pin_conflicts_with_continuation.
	// PinConflictReason is the verbatim client-facing message.
	PinConflict       bool
	PinConflictReason string

	// PriceBlocked is set when a caller `max_price` ceiling excluded every
	// otherwise-eligible operator (operators with an undeclared rate are
	// treated as too expensive). Surfaced as 400 price_ceiling_exceeded.
	PriceBlocked bool

	// ToolUnsupported is set when the caller required built-in tools
	// (`provider.require_tools`) and no operator serving/fitting the model
	// advertises every requested zs_* tool. Surfaced as 503
	// no_tool_capacity, paralleling no_tee_capacity (a required-capability
	// gap, not a malformed request).
	ToolUnsupported bool
}

// sizingMiss is the per-operator capacity envelope captured when Fits
// rejects a candidate. Both fields are pulled directly from
// op.ModelCapacities[req.Model]; a zero value means "the operator did
// not declare that limit" (Fits treats 0 as unbounded), so describeMiss
// shouldn't blame a 0 limit for the rejection.
type sizingMiss struct {
	OperatorID      uint64
	ContextWindow   uint64
	MaxOutputTokens uint64
	// EffectiveMaxOutput is the max_output the sizing filter actually charged
	// this operator (selection.SizingMiss.EffectiveMaxOutput): the flat request
	// value, or — when the caller omitted max_output (derive mode) — the
	// per-operator value from selection.DeriveMaxOutput. describeMiss reports the
	// gap from THIS, not sizing.MaxOutputTokens (which in derive mode holds the
	// flat display ceiling the caller never sent).
	EffectiveMaxOutput uint64
}

// formatNoFitMessage builds the error body for the "registry has
// candidates but none fit" branch. The leading line preserves the
// original wording (clients may match on it); when at least one miss
// was captured, a per-operator breakdown follows so the user can see
// which limit is being blown out and by how much. Splitting the gap
// on context_window vs max_output_tokens mirrors Fits's own check
// order, so the reason we report matches the reason we rejected.
// noFitMaxOutputLabel renders the max_output portion of a no-fit header. When
// the caller specified max_output (or a per-model default applied) it's the
// concrete flat value every operator was fit-checked against. In derive mode
// there is no single request-level value — each operator is charged its own
// derived ceiling (shown per-operator in the breakdown lines), so the header
// says so rather than printing the flat display ceiling the caller never sent.
// The documented client-match prefix ends at input_tokens, so this suffix is
// free to be non-numeric.
func noFitMaxOutputLabel(sizing hayai.SizingRequest) string {
	if sizing.DeriveMaxOutput {
		return "derived-per-operator"
	}
	return strconv.FormatUint(sizing.MaxOutputTokens, 10)
}

func formatNoFitMessage(model string, sizing hayai.SizingRequest, misses []sizingMiss) string {
	head := fmt.Sprintf("no operator serves %s with input_tokens=%d max_output_tokens=%s",
		model, sizing.InputTokens, noFitMaxOutputLabel(sizing))
	if len(misses) == 0 {
		return head
	}
	var b strings.Builder
	b.WriteString(head)
	b.WriteString("\n  operators advertising this model:")
	for _, m := range misses {
		b.WriteString("\n  - ")
		b.WriteString(describeMiss(m, sizing))
	}
	return b.String()
}

// describeMiss returns a one-line explanation of why a single operator
// failed Fits. Order matches Fits: context-window first (the combined
// input+max_output ceiling), then the standalone max_output cap. A 0
// limit means "undeclared/unbounded" — Fits would not have rejected on
// that axis, so describeMiss shouldn't blame it. The fallthrough
// message is defensive: if Fits ever grows a new check, we still emit
// a line per operator instead of going silent.
//
// The max_output term is m.EffectiveMaxOutput — the value the filter
// actually charged this operator — NOT req.MaxOutputTokens. They differ in
// derive mode (caller omitted max_output): req.MaxOutputTokens then holds
// the flat display ceiling while each operator was fit-checked against its
// own per-operator derivation, so blaming the flat ceiling would overstate
// the gap (and cite a max_output the caller never sent).
func describeMiss(m sizingMiss, req hayai.SizingRequest) string {
	if m.ContextWindow > 0 {
		need := req.InputTokens + m.EffectiveMaxOutput
		if need > m.ContextWindow {
			return fmt.Sprintf("op %d: context_window=%d (request needs %d)",
				m.OperatorID, m.ContextWindow, need)
		}
	}
	if m.MaxOutputTokens > 0 && m.EffectiveMaxOutput > m.MaxOutputTokens {
		return fmt.Sprintf("op %d: max_output_tokens=%d (over by %d)",
			m.OperatorID, m.MaxOutputTokens, m.EffectiveMaxOutput-m.MaxOutputTokens)
	}
	return fmt.Sprintf("op %d: declared capacity does not fit (context_window=%d, max_output_tokens=%d)",
		m.OperatorID, m.ContextWindow, m.MaxOutputTokens)
}

// resolveResponseIDPin looks up the operator pinned for previousResponseID
// and validates it can serve this request. Returns (operator, true) when
// the pin is honorable; otherwise returns (reason, _, false) where reason
// is a client-facing explanation of why the pin couldn't be honored.
//
// Failure modes are all surfaced to the client as 400 invalid_request,
// not 503 — the client supplied a continuation reference we can't honor,
// and the only sensible recovery is for them to retry without it.
func (s *Server) resolveResponseIDPin(ctx context.Context, previousResponseID, model string, sizing hayai.SizingRequest) (string, hayai.Operator, bool) {
	opID, nodeID, ok := s.responseAffinity.Lookup(previousResponseID)
	if !ok {
		return fmt.Sprintf("previous_response_id %q not found in routing cache; "+
			"the conversation may have expired or been served by a different "+
			"proxy replica — retry without previous_response_id",
			previousResponseID), hayai.Operator{}, false
	}
	// The session lives in the serving node's upstream account, so the pin
	// resolves the EXACT (operator, node) — a sibling node of the same operator
	// would 404 the continuation just as a different operator would.
	op, err := s.registryProvider.Resolve(ctx, opID, nodeID)
	if err != nil {
		s.log.Debug("response_id pin: node not in registry",
			slog.String("previous_response_id", previousResponseID),
			slog.Uint64("operator_id", opID),
			slog.Uint64("node_id", nodeID),
			slog.Any("err", err))
		return fmt.Sprintf("previous_response_id %q is pinned to operator %d node %d which is no longer registered; "+
			"retry without previous_response_id",
			previousResponseID, opID, nodeID), hayai.Operator{}, false
	}
	if !op.ServesModel(model) {
		return fmt.Sprintf("previous_response_id %q is pinned to operator %d which no longer serves model %q",
			previousResponseID, opID, model), hayai.Operator{}, false
	}
	if !hayai.Fits(op, sizing) {
		// Report the max_output this operator was actually fit-checked against
		// (per-operator derived in derive mode), not the flat display ceiling.
		return fmt.Sprintf("previous_response_id %q is pinned to operator %d which cannot fit input_tokens=%d max_output_tokens=%d; "+
			"reduce prompt size or start a new conversation",
			previousResponseID, opID, sizing.InputTokens, hayai.EffectiveMaxOutput(op, sizing)), hayai.Operator{}, false
	}
	return "", op, true
}

// poolMaxOutput returns the largest max_output_tokens advertised for model
// across the operators this request could actually be routed to, or 0 when they
// declare no ceiling worth clamping a caller to (see hayai.MaxDeclaredOutput for
// the "any operator undeclared ⇒ unbounded ⇒ don't clamp" rule).
//
// Filtering to the ROUTABLE set is what makes the answer usable, because
// MaxDeclaredOutput's undeclared-disables-everything rule turns a single
// unreachable operator into a pool-wide opt-out. registryProvider.Operators
// filters on ServesModel alone, so the raw list still holds staging nodes,
// nodes banned for a fraudulent settle group, and operators the caller's own
// `provider` preferences exclude — and a staging node that answered the setup
// wizard's max_output_tokens prompt with 0 ("no separate cap") would silently
// switch the clamp off for every payer on that model, resurfacing the exact
// context_length_exceeded this exists to prevent.
//
// This reads the registry a second time (pickCandidates reads it again with the
// sizing this call is what produces — the estimate can't run until the body is
// clamped, so the order can't be collapsed). Both hit the same cached snapshot:
// a scan and one slice, no probe.
//
// A registry error yields 0 — the clamp stays out of the way and pickCandidates
// surfaces the real failure with its own diagnostics.
func (s *Server) poolMaxOutput(ctx context.Context, model string, requireTEE bool, prefs selection.RoutingPreferences) uint64 {
	registry, err := s.registryProvider.Operators(ctx, model)
	if err != nil {
		return 0
	}
	routable := make([]hayai.Operator, 0, len(registry))
	for _, op := range registry {
		if s.routableIgnoringSize(op, requireTEE, prefs) {
			routable = append(routable, op)
		}
	}
	return hayai.MaxDeclaredOutput(routable, model)
}

// routableIgnoringSize reports whether op could serve this request if token
// counts were no object — every hard exclusion the selection path applies that
// does NOT depend on the numbers the clamp is trying to produce.
//
// Deliberately the hard excludes only. max_price is left out because it needs
// the pricing pass inside SelectTargets, and ranking signals (latency,
// diversity, affinity) are left out because they reorder rather than exclude.
// That asymmetry is safe in one direction and only one: keeping an operator
// that selection would later drop can only make the ceiling LARGER, which
// clamps less and leaves the request behaving exactly as it did before the
// clamp existed. Dropping one selection would have KEPT is the direction that
// does damage — it would clamp a caller below what an operator was ready to
// serve — so every predicate here must be one selection applies
// unconditionally. Each mirrors a check the response-id pin path above already
// makes against a single operator.
func (s *Server) routableIgnoringSize(op hayai.Operator, requireTEE bool, prefs selection.RoutingPreferences) bool {
	// Permanent, process-lifetime ban for a proven-fraudulent settle group —
	// pickCandidates drops these before it counts the registry at all.
	if s.nodeExcluder != nil && s.nodeExcluder.NodeExcluded(hayai.RefOf(op)) {
		return false
	}
	// On-chain NodeRecord.staging, held out unless the payer opted in
	// (zs.allow_staging / --allow-staging). Mirrors SelectTargets' staging step.
	if op.Staging && !s.cfg.AllowStaging {
		return false
	}
	if !wire.ProtoVersionCompatible(op.ProtoVersion) {
		return false
	}
	if requireTEE && !op.IsTEEAttested() {
		return false
	}
	// Signer below the routing floor. Mirrors SelectTargets' unconditional
	// funding step, via the same shared predicate.
	if op.SignerUnderfunded() {
		return false
	}
	// only / ignore / a no-fallback order — the shared primitive, so this agrees
	// with SelectTargets by construction rather than by re-derivation.
	return prefs.AllowsOperator(op.Selection())
}

// pickCandidates returns the ordered list of operators to try for this
// request. Order of operations: registry (model-filter) → sizing filter
// → TEE filter (if required) → affinity reorder.
//
// Sizing rules are in hayai.Fits: operators with no declared capacity
// for the request's model are treated as unbounded, so this filter is a
// no-op until an operator's registry entry carries ModelCapacities.
//
// Affinity interaction: sizing runs *before* affinity. Under
// AffinityStrict, if the affinity target was filtered out by sizing,
// the returned list is empty and AffinityBlocked is set — we don't
// silently relocate a tool-calling conversation to a different
// operator. Under AffinityPrefer, the target is simply re-ranked to the
// top of the surviving list; if it got filtered out, the next best
// operator wins.
//
// requireTEE: when true, operators without IsTEEAttested() are dropped
// after sizing and before affinity. The order matters — a TEE-required
// request must not get affinity-pinned to a non-attested operator. If
// no operator survives the TEE filter, pickResult.TEEBlocked is set
// and Operators is empty; dispatchHayai then returns 503 no_tee_capacity.
func (s *Server) pickCandidates(ctx context.Context, endpoint, model string, body []byte, sizing hayai.SizingRequest, requireTEE bool, toolBudgets selection.ImageToolBudgets, prefs selection.RoutingPreferences) (pickResult, error) {
	registry, err := s.registryProvider.Operators(ctx, model)
	if err != nil {
		return pickResult{}, err
	}
	// Hard-drop nodes proven to have handed a fraudulent atomic settle group.
	// Unlike the reachability/backoff signals this exclusion is permanent for the
	// process lifetime (see malicious_nodes.go) — filter before RegistryCount so
	// the empty-candidate 503 diagnostics reflect it. New slice: never mutate the
	// registry provider's returned slice.
	if s.nodeExcluder != nil {
		filtered := make([]hayai.Operator, 0, len(registry))
		for _, op := range registry {
			if s.nodeExcluder.NodeExcluded(hayai.RefOf(op)) {
				continue
			}
			filtered = append(filtered, op)
		}
		registry = filtered
	}
	res := pickResult{RegistryCount: len(registry)}

	// Responses-API session pin: if the client supplied
	// previous_response_id, the only correct route is the operator that
	// emitted the matching response_id — OpenAI's session state lives in
	// that operator's account, so any other operator's account would 404.
	// This pin is honored regardless of the configured affinity_policy
	// (correctness, not preference) and on cache miss we block rather
	// than fall through. The client should retry without
	// previous_response_id (the TUI's history accumulation is the
	// natural fallback).
	if endpoint == endpointResponses && s.responseAffinity != nil {
		if rid := hayai.ExtractPreviousResponseID(body); rid != "" {
			if reason, op, ok := s.resolveResponseIDPin(ctx, rid, model, sizing); !ok {
				res.AffinityBlocked = true
				res.AffinityBlockReason = reason
				return res, nil
			} else if !wire.ProtoVersionCompatible(op.ProtoVersion) {
				// Wire-protocol incompatibility overrides response-id
				// pinning, same shape as the TEE branch below: the
				// alternative would be sealing a request with this
				// build's envelope crypto and shipping it to a peer
				// that speaks a different wire generation — the
				// failure surfaces mid-flight as an opaque crypto
				// error instead of the clean 503 the rest of the path
				// produces. Surfacing VersionBlocked here lets the
				// client drop the pin and retry on a fresh session.
				res.VersionBlocked = true
				return res, nil
			} else if requireTEE && !op.IsTEEAttested() {
				// TEE requirement overrides response-id pinning:
				// the alternative would be silently routing a
				// confidential-mode-required request to a
				// non-attested operator that happens to hold the
				// continuation. Better to surface the conflict so
				// the client can drop the pin and retry.
				res.TEEBlocked = true
				return res, nil
			} else if !prefs.AllowsOperator(op.Selection()) {
				// Caller routing-preference vs continuation conflict: the
				// session lives in this exact operator's upstream account, but
				// the caller's hard preferences (only / ignore / a no-fallback
				// order) exclude it. We can serve EITHER the continuation OR the
				// pin, not both — so surface the conflict rather than silently
				// violate one. This is a client contradiction (400), distinct
				// from a pool-availability pin miss (ProviderPinBlocked, 503):
				// the client drops the conflicting pin or starts a new
				// conversation; retrying the same body never resolves it.
				res.PinConflict = true
				res.PinConflictReason = fmt.Sprintf(
					"previous_response_id %q is pinned to operator %d node %d, which your provider "+
						"preferences (only/ignore/order) exclude; the continuation can only be served by "+
						"that operator — remove the conflicting preference or start a new conversation",
					rid, op.ID, op.NodeID)
				return res, nil
			} else if op.SignerUnderfunded() {
				// The continuation's node can't pay the fees of the open it would
				// sign. After the conflict checks so a permanent contradiction is
				// reported ahead of this transient one; the session survives, so
				// the client can retry the same pin once the operator tops up.
				res.SignerUnderfundedBlocked = true
				res.SignerUnderfundedReason = fmt.Sprintf(
					"previous_response_id %q is pinned to operator %d node %d, whose signing account has less than %d ALGO "+
						"spendable to pay network fees; retry once the operator tops up, or start a new conversation",
					rid, op.ID, op.NodeID, selection.MinSignerSpendableMicroAlgos/1_000_000)
				return res, nil
			} else {
				res.Operators = []hayai.Operator{op}
				return res, nil
			}
		}
	}

	// The eligibility / sizing / version / TEE / built-in-tool / affinity
	// policy is the shared proto primitive (selection.SelectTargets), so the
	// proxy and the client/ app pick identically (golden-vectored in
	// proto/testdata/selection_vectors.json). The proxy keeps only the
	// runtime glue around it: the response-id strict pin (above, which needs
	// the live responseAffinity cache + registry resolve), the tool-affinity
	// cache lookup (below), and the diagnostics→HTTP-status mapping in
	// dispatchHayai.

	// Resolve the tool-affinity preferred operator. The cache lookup + the
	// registry resolve are runtime state and stay here; SelectTargets applies
	// the serves/fits/strict/prefer rules. preferred stays nil when affinity
	// is off, there's no cache hit, or the hit doesn't resolve in the
	// registry (all of which mean "no affinity preference").
	var preferred *selection.Operator
	var preferredHayai *hayai.Operator
	if s.cfg.Affinity != hayai.AffinityNone && s.toolAffinity != nil {
		for _, id := range hayai.ExtractInputToolCallIDs(body) {
			if opID, nodeID, ok := s.toolAffinity.Lookup(id); ok {
				// Resolve the EXACT (operator, node) that served the prior turn
				// — KV-cache reuse is per-node, so the preferred descriptor must
				// carry the node. SelectTargets ranks it first (prefer) or pins
				// it (strict); siblings stay eligible fallbacks (prefer).
				if op, err := s.registryProvider.Resolve(ctx, opID, nodeID); err == nil {
					sel := op.Selection()
					preferred = &sel
					preferredHayai = &op
				} else {
					s.log.Debug("affinity-preferred node not in registry",
						slog.Uint64("operator_id", opID),
						slog.Uint64("node_id", nodeID),
						slog.Any("err", err))
				}
				break
			}
		}
	}

	selOps := make([]selection.Operator, len(registry))
	for i, op := range registry {
		selOps[i] = op.Selection()
	}
	// Image-tool budgets gate the in-loop image-tool partition in SelectTargets
	// (prefer operators whose chosen model publishes the matching factor). This
	// mirrors the reserve-loop's per-tool skip below — but as a *ranking* so the
	// first candidate is already tool-capable in the common case, leaving the
	// skip as the rare backstop. These are the same budgets dispatchHayai parsed
	// and clamped once for the reserve loop, threaded in here so both read one
	// source of truth (only >0 matters to the partition, so the clamp is
	// immaterial to it — but a single parse keeps the two in lockstep).
	tr := selection.SelectTargets(selOps, selection.Constraints{
		Model:           model,
		InputTokens:     sizing.InputTokens,
		InputTokensV2:   sizing.InputTokensV2,
		MaxOutputTokens: sizing.MaxOutputTokens,
		// Derive the fit-check max_output per-operator when the caller omitted it
		// (mirrors sizing + hayai.Fits + the reserve loop), so the shared policy
		// admits small-window operators the flat ceiling would have dropped.
		MaxOutputUnspecified: sizing.DeriveMaxOutput,
		MaxOutputCeiling:     sizing.MaxOutputCeiling,
		Endpoint:             endpoint,
		RequireTEE:           requireTEE,
		AllowStaging:         s.cfg.AllowStaging,
		RequestedTools:       hayai.ExtractRequestedHayaiTools(body),
		ImageToolGenBudget:   toolBudgets.GenerationMaxN,
		ImageToolEditBudget:  toolBudgets.EditMaxN,
		AffinityPolicy:       string(s.cfg.Affinity),
		// Caller routing preferences (the `provider` object). The shared policy
		// applies only/ignore/order/max_price/require_tools; the app-side sort
		// and relay overrides (prefs.Sort / prefs.Relay) are consumed elsewhere.
		Only:              prefs.Only,
		Ignore:            prefs.Ignore,
		Order:             prefs.Order,
		AllowFallbacks:    prefs.AllowFallbacks,
		MaxInputUSDPer1M:  prefs.MaxInputUSDPer1M,
		MaxOutputUSDPer1M: prefs.MaxOutputUSDPer1M,
		RequireTools:      prefs.RequireTools,
	}, preferred)

	// Map selection diagnostics back onto pickResult so dispatchHayai emits
	// the same 503/400 bodies. RegistryCount is already set above and equals
	// tr.Diagnostics.RegistryCount.
	res.VersionBlocked = tr.Diagnostics.VersionBlocked
	res.TEEBlocked = tr.Diagnostics.TEEBlocked
	res.StagingBlocked = tr.Diagnostics.StagingBlocked
	res.SignerUnderfundedBlocked = tr.Diagnostics.SignerUnderfundedBlocked
	if res.SignerUnderfundedBlocked && preferredHayai != nil && preferredHayai.SignerUnderfunded() &&
		s.cfg.Affinity == hayai.AffinityStrict {
		res.SignerUnderfundedReason = fmt.Sprintf(
			"this tool-call continuation is pinned (affinity_policy: strict) to operator %d node %d, whose signing account "+
				"has less than %d ALGO spendable to pay network fees; retry later, or set affinity_policy to prefer so another node can continue it",
			preferredHayai.ID, preferredHayai.NodeID, selection.MinSignerSpendableMicroAlgos/1_000_000)
	}
	res.ImageEndpointUnsupported = tr.Diagnostics.ImageEndpointUnsupported
	res.AffinityBlocked = tr.Diagnostics.AffinityBlocked
	res.ProviderPinBlocked = tr.Diagnostics.ProviderPinBlocked
	res.PriceBlocked = tr.Diagnostics.PriceBlocked
	res.ToolUnsupported = tr.Diagnostics.ToolUnsupported
	for _, m := range tr.Diagnostics.SizingMisses {
		res.SizingMisses = append(res.SizingMisses, sizingMiss{
			OperatorID:         m.OperatorID,
			ContextWindow:      m.ContextWindow,
			MaxOutputTokens:    m.MaxOutputTokens,
			EffectiveMaxOutput: m.EffectiveMaxOutput,
		})
	}

	// Map the ordered selection.Operator descriptors back to the proxy's
	// enriched records by id. The affinity-preferred operator is resolved
	// from the full registry and may not be in the model-filtered list, so
	// include it in the lookup. Leave res.Operators nil when empty (matches
	// the early-return paths above and dispatchHayai's len() check).
	if len(tr.Operators) > 0 {
		// Key by (operator id, node id) via the shared hayai.NodeRef: the
		// registry holds one Operator per node and SelectTargets orders distinct
		// nodes, so keying by operator id alone would collapse an operator's
		// nodes to whichever landed last — stranding the rest. With the node id
		// in the key every node stays independently dispatchable (same key type
		// the registry uses, and the mirror of the client's catalogRowsByNode).
		byNode := make(map[hayai.NodeRef]hayai.Operator, len(registry)+1)
		for _, op := range registry {
			byNode[hayai.RefOf(op)] = op
		}
		if preferredHayai != nil {
			byNode[hayai.RefOf(*preferredHayai)] = *preferredHayai
		}
		res.Operators = make([]hayai.Operator, 0, len(tr.Operators))
		for _, so := range tr.Operators {
			res.Operators = append(res.Operators, byNode[hayai.NodeRef{Op: so.ID, Node: so.NodeID}])
		}
		// Responsiveness post-pass: order by the caller's provider.sort band
		// (default: combined network RTT + on-chain TTFT + decode; latency:
		// first-token only; throughput: decode only; price: no reband), price
		// within band, with the affinity pin kept first — the "responsiveness
		// bands" policy mirrored from the client's dispatch-candidates. No-op when
		// no node has a responsiveness signal.
		var ranking []rankDetail
		res.Operators, ranking = bandByResponsiveness(res.Operators, preferredHayai, s.relayLatency, prefs.Sort)
		// Weights post-pass: demote a candidate whose advertised weights digest
		// contradicts what a majority of distinct owners advertise for this model.
		// Applied after the responsiveness order because it is a trust signal
		// rather than a speed one — being contradicted should cost placement no
		// matter how fast the node looks. Voted over the whole registry, not just
		// the eligible slice. See weights_trust.go for what this does and does not
		// catch.
		//
		// NO pin exemption, deliberately, and the nil here is the whole decision:
		// demoteContradictedWeights reserves that parameter for a genuine session
		// continuation, and NEITHER of the proxy's pins is one at this point.
		// The real continuation pin (previous_response_id → responseAffinity) has
		// already returned a single-operator list far above and never reaches this
		// code. What survives to here is only `preferredHayai`, the TOOL-CALL
		// affinity pin — and under `strict` SelectTargets has already collapsed
		// the list to that one operator, so the exemption could only ever fire
		// under `prefer`, where the pin is a KV-cache preference and nothing more.
		// Exempting a preference would make the demerit inert for the payer
		// already bound to the contradicted operator across a whole tool loop
		// (affinity TTL, 10m default) — precisely who is paying for a substituted
		// model, and precisely the case client/ refuses to exempt. Matching it.
		var weightsDemoted []hayai.NodeRef
		res.Operators, weightsDemoted = demoteContradictedWeights(res.Operators, nil, registry, model)
		s.warnWeightsContradiction(model, weightsDemoted)
		// Backoff post-pass, applied LAST so it outranks the responsiveness order:
		// a node that keeps failing us is worth avoiding even when it looks fast
		// (its RTT sample is stale by definition — we haven't completed a request
		// against it). Demote, never drop, mirroring the client: a model only one
		// node serves must stay reachable as a last resort, and the window only
		// lapses because live traffic re-probes it.
		res.Operators = demoteBackedOffTargets(res.Operators, preferredHayai, s.targetBackoff)
		s.logRanking(ctx, model, prefs.Sort, res.Operators, ranking)
	}
	return res, nil
}

// logRanking emits the final candidate order and the banding inputs behind it.
// Without it "why did it pick that operator?" is unanswerable after the fact: the
// price sort, the responsiveness terms, the confidence discount and the backoff
// demotion are all silent, and the only surviving evidence is the winner's ticket
// rates once its reserve has already succeeded.
//
// ranking is nil whenever no banding ran (SortPrice, <2 candidates, or no node
// with a signal) — the order is then purely the price sort, which the rates in
// each line already show.
//
// ops is the FINAL order, after demoteBackedOffTargets; ranking is the order
// bandByResponsivenessDetailed produced, so a candidate whose position differs
// between the two was moved by the backoff demotion. Matching by NodeRef rather
// than index is what keeps that legible.
//
// Rates, latency, ids and model names are all loggable; no request content is
// involved.
func (s *Server) logRanking(ctx context.Context, model, sort string, ops []hayai.Operator, ranking []rankDetail) {
	if !s.log.Enabled(ctx, slog.LevelDebug) || len(ops) == 0 {
		return
	}
	byRef := make(map[hayai.NodeRef]rankDetail, len(ranking))
	for _, d := range ranking {
		byRef[d.ref] = d
	}
	lines := make([]any, 0, len(ops))
	for i, op := range ops {
		ref := hayai.RefOf(op)
		mc := op.ModelCapacities[model]
		attrs := []any{
			slog.Int("rank", i),
			slog.Uint64("operator_id", ref.Op),
			slog.Uint64("node_id", ref.Node),
			slog.Float64("input_usd_per_1m", mc.InputUSDPer1M),
			slog.Float64("output_usd_per_1m", mc.OutputUSDPer1M),
		}
		if d, ok := byRef[ref]; ok {
			attrs = append(attrs,
				slog.Int("catalog_models", d.catalog),
				slog.Float64("metrics_confidence", d.confidence),
				slog.Group("rtt", "raw", d.rtt.value, "confidence", d.rtt.confidence, "effective", d.rttEff),
				slog.Group("ttft", "raw", d.ttft.value, "confidence", d.ttft.confidence, "effective", d.ttftEff),
				slog.Group("decode", "raw", d.decode.value, "confidence", d.decode.confidence, "effective", d.decodeEff),
				slog.Float64("score_ms", d.score),
				slog.Float64("band", d.band),
				slog.Bool("signal", d.signal),
				slog.Bool("pinned", d.pinned),
			)
		}
		lines = append(lines, slog.Group(strconv.Itoa(i), attrs...))
	}
	s.log.Debug("target ranking",
		slog.String("model", model),
		slog.String("sort", cmp.Or(sort, "balanced")),
		slog.Bool("banded", ranking != nil),
		slog.Group("candidates", lines...))
}

// demoteBackedOffTargets moves nodes inside an active dispatch-failure window to
// the tail, preserving relative order within each group (stable partition).
//
// The affinity/continuation pin is exempt: when it is present it is the only
// correct route (the upstream session or KV cache lives on that exact node), so
// reordering it would trade a working continuation for a routing preference. It
// is already first and stays first.
//
// Nil store (tests) or nothing backed off returns ops untouched.
func demoteBackedOffTargets(ops []hayai.Operator, preferred *hayai.Operator, bo hayai.TargetBackoff) []hayai.Operator {
	if bo == nil || len(ops) < 2 {
		return ops
	}
	var pinned hayai.NodeRef
	if preferred != nil {
		pinned = hayai.RefOf(*preferred)
	}
	ok := make([]hayai.Operator, 0, len(ops))
	demoted := make([]hayai.Operator, 0)
	for _, op := range ops {
		ref := hayai.RefOf(op)
		if preferred != nil && ref == pinned {
			ok = append(ok, op)
			continue
		}
		if bo.TargetBackedOff(ref) {
			demoted = append(demoted, op)
			continue
		}
		ok = append(ok, op)
	}
	if len(demoted) == 0 {
		return ops
	}
	return append(ok, demoted...)
}

// targetResponsivenessBandMS is the responsiveness band width (ms). Targets are
// bucketed by their responsiveness score; a target only outranks a cheaper peer
// when it's ~one band faster, so small differences never reorder (price decides
// within a band) while a slow CPU node lands a band or more back from a fast GPU
// one. Mirror of the client's TARGET_RESPONSIVENESS_BAND_MS. Tunable.
const targetResponsivenessBandMS = 500.0

// maxBandsFromMedian bounds how far responsiveness may move a candidate from the
// pack. Every term in the score is ultimately a speed PROXY rather than a
// measurement of this request on this model (see catalogConfidence), so an
// unbounded band spread lets a large apparent speed edge override an arbitrarily
// large price advantage. Clamping to one band either side leaves three buckets —
// ahead of / with / behind the pack — and hands every finer distinction back to
// price. Mirror of the client's MAX_BANDS_FROM_MEDIAN. Tunable.
const maxBandsFromMedian = 1.0

// decodeNormTokens is the fixed "typical response length" that turns a node's
// on-chain tokens/sec into a comparable ms term (decodeNormTokens/tps·1000). It
// sets how much decode speed weighs, and is sized so the term lands in TTFT's
// magnitude — a balanced blend, not a dominant one, because the tok/s aggregate
// is the noisiest signal we have (per-node, and decode rate is model-size-
// dominated).
//
// It was 128, which did not do that: the term ran 1600ms at 80 tok/s to 6400ms
// at 20 tok/s — three to thirteen bands — while TTFT spans roughly one, so decode
// quietly decided the entire ordering and price never got a say. At 32 it runs
// 400–1600ms, which is the magnitude this constant was always documented to
// produce.
//
// NOT the request's max_output_tokens (an inflated upper bound that would swamp
// the score). Mirror of the client's DECODE_NORM_TOKENS. Tunable.
const decodeNormTokens = 32.0

// catalogConfidence weighs a node's on-chain speed aggregates by how much of its
// traffic could have been a model other than the one we're routing.
//
// The chain holds exactly ONE latency_ewma_ms and one tokens_per_sec_ewma per
// node (NodeRecord), folded on every settled request regardless of model —
// settle() carries no model argument, deliberately, since putting model identity
// on chain per settlement would open a fresh linkage channel against payer
// unlinkability. So each number is a traffic-weighted mean over whatever mix the
// node happens to serve. A node serving one model reports that model's real
// figure; a node serving thirty small fast models plus this one reports something
// dominated by the small ones. Comparing the two as equals is what let a
// broad-catalog node outrank a cheaper specialist on a number that was never
// about this model.
//
// Every candidate serves the requested model by construction, so catalog breadth
// measures exactly one thing here: how much OTHER traffic dilutes the aggregate.
//
// This is deliberately pessimistic and is NOT a dilution estimate. The aggregate
// is traffic-weighted and we cannot observe traffic — a node with thirty models
// that serves 95% of its requests on this one has a perfectly good aggregate and
// still gets discounted. Breadth is an upper bound on possible dilution, so this
// discounts whenever dilution can't be ruled out. That direction is the right one
// (a fabricated speed edge costs the payer money; a missed real one costs some
// latency), and what restores the ability to reward genuine speed is a
// locally-observed per-(node, model) sample, not a cleverer guess here.
//
// Only TOKEN-OUTPUT models are counted. The contract folds both aggregates
// exclusively on token-output settles (`outputUsageType === USAGE_TOKENS` in
// ZeroSignalEscrow.algo.ts' settle metrics block — TTFT and tokens/sec describe a
// token stream, so an image settle leaves them untouched), so an image-only model
// contributes no sample and cannot dilute anything. Counting it anyway discounts
// on a route that never wrote to the number: a node serving one text model beside
// 99 image models would score 0.10 and lose a speed signal that is, in fact,
// entirely about its one text model.
//
// A model with UNDECLARED output modalities counts, like an undeclared catalog
// scores 0 — unknown means "assume it dilutes", keeping the discount pessimistic
// where evidence is missing rather than only where it's damning.
//
// 1/sqrt(n): 1 model → 1.00, 4 → 0.50, 16 → 0.25. A starting curve, not a derived
// constant. An undeclared catalog scores 0 — unknown breadth means unbounded
// possible dilution. A node whose catalog is declared but entirely image-only
// lands there too, which is right for a different reason: the chain holds no
// token-stream evidence about it at all, so "no information, mid-pack" is exactly
// the verdict. Mirror of the client's catalogConfidence.
func catalogConfidence(op hayai.Operator) float64 {
	n := 0
	for _, mc := range op.ModelCapacities {
		if producesTokens(mc.OutputModalities) {
			n++
		}
	}
	if n < 1 {
		return 0
	}
	return 1 / math.Sqrt(float64(n))
}

// producesTokens reports whether a model can settle as token output — the only
// settles that move latencyEwmaMs / tokensPerSecEwma. Undeclared modalities read
// as yes (see catalogConfidence). Mirror of the client's `producesTokens`.
func producesTokens(outputModalities []string) bool {
	if len(outputModalities) == 0 {
		return true
	}
	for _, m := range outputModalities {
		if strings.EqualFold(m, "text") {
			return true
		}
	}
	return false
}

// responsivenessTerm is one input to a target's responsiveness score: a raw value
// in ms, plus the confidence that the value describes THIS request's model on
// THIS node. bandByResponsiveness shrinks each term toward the candidate-set
// median by its confidence, so 1 uses the value as measured and 0 yields the
// median — "no information, mid-pack".
//
// wanted is deliberately separate from a zero confidence: the caller's sort mode
// drops whole terms from the score, and a dropped term must not count toward
// `signal` the way an unfilled-but-wanted one does.
type responsivenessTerm struct {
	value      float64
	confidence float64
	wanted     bool
}

// responsivenessTerms breaks a target's expected response time (lower = faster,
// in ms) into the delays a user waits through, each with the confidence that it
// describes the model being routed:
//
//   - RTT — client-observed network round trip. Confidence 1 with enough fresh
//     samples, else 0. Network time is model-independent, so this is the one term
//     whose comparison across candidates is sound as measured.
//   - TTFT — the node's on-chain co-signed first-token EWMA
//     (Metrics.LatencyEwmaMs), discounted by catalogConfidence.
//   - decode — the rest of the response, from the on-chain tokens/sec EWMA
//     (Metrics.TokensPerSecEwma) normalized to decodeNormTokens, discounted the
//     same way.
//
// Additive, every term lower-is-faster, so banding stays uniform.
//
// mode is the caller's `provider.sort` and selects which terms are wanted:
//   - ""                       (default) → all three: combined expected response time.
//   - selection.SortLatency    → RTT + TTFT (time to first token).
//   - selection.SortThroughput → the decode term only (lower decode-time ⇔ higher
//     tokens/sec, so banding orders by sustained throughput).
//
// (SortPrice never reaches here — bandByResponsiveness skips the reband for it.)
//
// Terms come back SEPARATELY, never pre-summed, because a term we can't fill
// cannot be scored in isolation: dropping it contributes ZERO to an additive
// lower-is-faster score — it reads as "infinitely fast". That is why every term
// carries a confidence rather than a present/absent bool, and why the caller
// substitutes the median rather than 0. It was a live exploit on the decode term:
// decode_ms is self-reported on the operator's receipt, so at decodeNormTokens=128
// an honest node at 40 tok/s paid 3200ms while a node that never emitted a
// parseable usage chunk paid 0 and outranked it by six bands — withholding the
// metric beat reporting it.
//
// Rejected alternative: requiring every wanted term for `signal`. That sends a
// node to the median band overall, but it also discards real RTT/TTFT
// discrimination — and tokens/sec only exists after a settled token receipt, so
// most of the fleet lacks it and banding would have gone dark.
//
// Residual worth knowing: a discounted or absent term still beats being honestly
// SLOW, since the median is by construction better than the worst candidate. This
// bounds the incentive rather than closing it; only stake or attestation could.
// Mirrored in client/src/operators/dispatch-candidates.ts.
func responsivenessTerms(op hayai.Operator, lat hayai.RelayLatency, mode string) (rtt, ttft, decode responsivenessTerm) {
	wantFirstToken := mode != selection.SortThroughput // RTT + TTFT
	wantDecode := mode != selection.SortLatency        // tok/s term
	chain := catalogConfidence(op)

	rtt.wanted = wantFirstToken
	if wantFirstToken && lat != nil {
		if ms, n, ok := lat.TargetLatency(hayai.RefOf(op)); ok && n >= hayai.LatencyMinSamples {
			rtt.value, rtt.confidence = ms, 1
		}
	}
	ttft.wanted = wantFirstToken
	if wantFirstToken {
		if ms := op.Metrics.LatencyEwmaMs; ms > 0 {
			ttft.value, ttft.confidence = float64(ms), chain
		}
	}
	decode.wanted = wantDecode
	if wantDecode {
		if tps := op.Metrics.TokensPerSecEwma; tps > 0 {
			decode.value, decode.confidence = decodeNormTokens/float64(tps)*1000, chain
		}
	}
	return rtt, ttft, decode
}

// shrinkToMedian returns each term's effective contribution to the score:
// median + confidence·(value − median), over the confident values in terms. An
// unwanted term contributes 0.
//
// Toward the MEDIAN, never toward zero. On an additive lower-is-faster score,
// scaling an untrusted term down (confidence·value) makes the node look FASTER —
// the same infinitely-fast trap that omitting a term causes.
//
// The shrink is affine, so candidates sharing a confidence keep their exact
// relative order and only their spread compresses. Banding then rounds that
// compressed spread, so the visible effect is that price wins more ties.
// Discrimination is lost only where confidences differ — which is precisely where
// the comparison was invalid to begin with.
//
// The median is confidence-WEIGHTED, and that is load-bearing rather than a
// refinement. A candidate sitting exactly at the median is unmoved by the shrink
// at any confidence (value = med ⇒ eff = med), so with a plain one-vote-each
// median a MAJORITY of diluted candidates defines the reference point and then
// keeps its flattering numbers in full, while the lone trustworthy specialist
// keeps its honest — worse — number and is buried. That is the reported bug
// returning intact whenever broad-catalog nodes outnumber specialists, which on a
// fleet of aggregators is the normal case, not the corner one. Weighting each
// value by its own confidence is what stops untrusted numbers from defining
// "the pack" they are then measured against.
func shrinkToMedian(terms []responsivenessTerm) []float64 {
	var values, weights []float64
	for _, t := range terms {
		if t.wanted && t.confidence > 0 {
			values = append(values, t.value)
			weights = append(weights, t.confidence)
		}
	}
	med := confidenceWeightedMedian(values, weights)
	out := make([]float64, len(terms))
	for i, t := range terms {
		if !t.wanted {
			continue
		}
		out[i] = med + t.confidence*(t.value-med)
	}
	return out
}

// confidenceWeightedMedian is the median of values where each counts for its
// weight rather than for one vote. Empty (or all-zero weight) is 0, mirroring
// medianOf, so a term nobody can fill still shrinks to a defined reference.
//
// It is the weighted quantile at p=0.5, interpolated between the two values
// bracketing the half-weight point. The interpolation is what makes it a strict
// generalization of medianOf: at EQUAL weights it reproduces the plain median
// exactly, including the average-the-two-middles rule on an even count, so
// swapping it in changes nothing for the common candidate set where every
// confidence matches. Only a set with differing confidences moves — which is
// exactly the set the plain median got wrong.
//
// Interpolated rather than "first value past the half-weight point" on purpose:
// the latter needs an exact float equality on an accumulated sum to recover the
// even-count average, and that equality is not reliable once the weights are
// 1/sqrt(n) irrationals. Mirror of the client's confidenceWeightedMedian.
func confidenceWeightedMedian(values, weights []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	order := make([]int, len(values))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return values[order[a]] < values[order[b]] })
	var total float64
	for _, w := range weights {
		total += w
	}
	if total <= 0 {
		return 0
	}
	// pos[k] is the midpoint of element k's weight along the cumulative axis, so
	// a value "occupies" its own weight rather than sitting at the end of it —
	// the standard construction that makes equal weights land on the plain median.
	half := total / 2
	pos := make([]float64, len(order))
	var cum float64
	for k, i := range order {
		pos[k] = cum + weights[i]/2
		cum += weights[i]
	}
	for k, i := range order {
		if pos[k] < half {
			continue
		}
		if k == 0 {
			return values[i] // half-weight point falls at or before the first value
		}
		prev := order[k-1]
		span := pos[k] - pos[k-1]
		if span <= 0 {
			return values[i]
		}
		return values[prev] + (half-pos[k-1])/span*(values[i]-values[prev])
	}
	return values[order[len(order)-1]]
}

// rankDetail is one candidate's banding inputs and verdict, in final order.
// bandByResponsiveness hands these back so the dispatch path can log the decision
// it actually made rather than recomputing it — a recomputed log line is how a log
// drifts from its subject.
type rankDetail struct {
	ref        hayai.NodeRef
	catalog    int
	confidence float64
	rtt        responsivenessTerm
	ttft       responsivenessTerm
	decode     responsivenessTerm
	rttEff     float64
	ttftEff    float64
	decodeEff  float64
	score      float64
	band       float64
	pinned     bool
	signal     bool
}

// bandByResponsiveness is a stable responsiveness banding over an already
// price-ordered candidate list: score each target from the terms mode selects,
// bucket the scores into bands, order fastest band first, and keep PRICE order
// within each band — the "responsiveness bands" policy. A much-faster node (a GPU
// peer a band ahead) outranks a marginally-cheaper slow (CPU) one, while small
// differences never reorder.
//
// Two rules keep a speed proxy from overriding a real price advantage:
//
//   - Every term is shrunk toward the candidate-set median by its confidence
//     (shrinkToMedian), so a term we can't fill — or one diluted by a broad
//     catalog (catalogConfidence) — lands mid-pack rather than scoring as
//     infinitely fast. A node with NO confident term at all lands in the median
//     band, neither promoted nor buried.
//   - Bands are then clamped to one either side of the median
//     (maxBandsFromMedian), bounding the total displacement responsiveness may
//     cause.
//
// The affinity-preferred node (a continuity/correctness pin) is pinned first
// regardless of band. When NO node has any signal the list is returned untouched
// (price order). <2 candidates is a no-op; a nil RTT store still bands by the
// on-chain metrics.
//
// mode is the caller's `provider.sort` (selection.Sort*):
//   - selection.SortPrice → skip the reband entirely and return the price-ordered
//     list as-is (the caller asked for pure price; the affinity pin is already
//     first from SelectTargets, so no special-casing is needed).
//   - SortLatency / SortThroughput / "" → band by the terms responsivenessTerms
//     marks wanted for that mode.
//
// The second return is the per-candidate scoring detail, in the same final order;
// it is nil whenever no banding ran (SortPrice, a list too short to reorder, or a
// candidate set where nobody has any signal).
func bandByResponsiveness(ops []hayai.Operator, preferred *hayai.Operator, lat hayai.RelayLatency, mode string) ([]hayai.Operator, []rankDetail) {
	if mode == selection.SortPrice {
		return ops, nil
	}
	if len(ops) < 2 {
		return ops, nil
	}
	rtts := make([]responsivenessTerm, len(ops))
	ttfts := make([]responsivenessTerm, len(ops))
	decodes := make([]responsivenessTerm, len(ops))
	details := make([]rankDetail, len(ops))
	for i, op := range ops {
		rtts[i], ttfts[i], decodes[i] = responsivenessTerms(op, lat, mode)
		details[i] = rankDetail{
			ref:        hayai.RefOf(op),
			catalog:    len(op.ModelCapacities),
			confidence: catalogConfidence(op),
			rtt:        rtts[i],
			ttft:       ttfts[i],
			decode:     decodes[i],
			signal: rtts[i].wanted && rtts[i].confidence > 0 ||
				ttfts[i].wanted && ttfts[i].confidence > 0 ||
				decodes[i].wanted && decodes[i].confidence > 0,
		}
	}
	// Each term is shrunk toward the candidate-set median of that term by its own
	// confidence, so an unfilled or diluted term lands mid-pack instead of scoring
	// as infinitely fast. See shrinkToMedian for why the median and not zero.
	rttEff := shrinkToMedian(rtts)
	ttftEff := shrinkToMedian(ttfts)
	decodeEff := shrinkToMedian(decodes)

	var known []float64
	for i := range ops {
		details[i].rttEff, details[i].ttftEff, details[i].decodeEff = rttEff[i], ttftEff[i], decodeEff[i]
		details[i].score = rttEff[i] + ttftEff[i] + decodeEff[i]
		if details[i].signal {
			known = append(known, details[i].score)
		}
	}
	if len(known) == 0 {
		return ops, nil
	}
	medianBand := math.Round(medianOf(known) / targetResponsivenessBandMS)

	var prefRef hayai.NodeRef
	if preferred != nil {
		prefRef = hayai.RefOf(*preferred)
	}
	order := make([]int, len(ops))
	for i, op := range ops {
		band := medianBand
		if details[i].signal {
			band = math.Round(details[i].score / targetResponsivenessBandMS)
			// Bound how far responsiveness may move a candidate from the pack —
			// see maxBandsFromMedian.
			band = min(medianBand+maxBandsFromMedian, max(medianBand-maxBandsFromMedian, band))
		}
		details[i].band = band
		details[i].pinned = preferred != nil && hayai.RefOf(op) == prefRef
		order[i] = i
	}
	// Stable: equal bands keep input (price) order. The continuity pin is its own
	// sort key rather than a sentinel band, because the clamp above can produce a
	// band at or below the sentinel's old value.
	sort.SliceStable(order, func(a, b int) bool {
		x, y := details[order[a]], details[order[b]]
		if x.pinned != y.pinned {
			return x.pinned
		}
		return x.band < y.band
	})
	out := make([]hayai.Operator, len(ops))
	ordered := make([]rankDetail, len(ops))
	for i, idx := range order {
		out[i], ordered[i] = ops[idx], details[idx]
	}
	return out, ordered
}

// runHayaiSealed seals the request under the recipient pinned at reserve time
// (rt.SealRecipient — the operator's signed ephemeral recipient; mandatory
// forward secrecy, no anchor), dispatches it to op.BaseURL with the reserved
// ticket_id bound into the envelope, and hands the response to the decrypt
// pipeline.
func (s *Server) runHayaiSealed(
	w http.ResponseWriter,
	r *http.Request,
	endpoint, model string,
	body []byte,
	op hayai.Operator,
	rt *hayai.ReservedTicket,
	wantsStream bool,
	hop *hayai.RelayHop,
	format clientFormat,
) {
	ctx := r.Context()
	ticket := rt.Ticket
	algoUSDPrice := rt.AlgoUSDPrice

	// Spend guard: bound the *aggregate* USDC drain before committing money.
	// Reserve the ticket's MaxPrice (the upper bound the open group locks; the
	// actual charge is reconciled lower at settle) atomically against the
	// per-request + daily caps. Reserving before the open is the safe order —
	// the reservation holds the cap under concurrency; we Release it below if the
	// open fails. The reserve runs after the (already-paid) reserve round-trip,
	// so a cap trip wastes one operator reservation — acceptable for a rare
	// safety event. Nil guard (no caps configured) is a no-op.
	if s.spend != nil {
		if err := s.spend.Reserve(ticket.TicketID, ticket.MaxPrice); err != nil {
			// Two opposite diagnoses share this one return. A duplicate ticket id
			// is the OPERATOR reusing an id it already handed out (the guard
			// refuses it rather than letting the second request skip the cap check
			// and resolve the first one's reservation) — no local config change can
			// fix that, so reporting it as a cap breach would send the payer to a
			// knob that cannot help. Everything else is a genuine cap trip.
			if errors.Is(err, hayai.ErrDuplicateTicket) {
				s.log.Warn("operator reused a ticket id; refusing request",
					slog.String("endpoint", endpoint),
					opAttr(op),
					relayAttr(hop),
					slog.String("ticket_id", ticket.TicketID),
					slog.Any("err", err))
				writeError(w, newError("operator_ticket_reuse",
					"the operator issued a ticket id that is already in flight for this payer; no payment was made"))
				return
			}
			s.log.Warn("spend cap reached; refusing request",
				slog.String("endpoint", endpoint),
				slog.Uint64("max_price_microusdc", ticket.MaxPrice),
				slog.Any("err", err))
			writeError(w, newError("spend_cap_exceeded",
				"spend cap reached: this request would exceed the configured USDC limit — raise spend.daily_cap_usdc / spend.per_request_cap_usdc, or wait for the UTC day to roll over"))
			return
		}
	}

	// Compose + submit the Payment + escrow.open atomic group via the
	// wallet. The app-call txid (group member 1) is threaded into the
	// envelope's algorand_tx_id — the real per-txn id algod's
	// PendingTransactionInformation can look up directly. The group id
	// is retained on the handle for audit/dispute logging but is NOT
	// the lookup key.
	openHandle, err := s.wallet.Open(ctx, ticket, op, rt.PreSignedOpenGroup)
	if err != nil {
		// The open didn't commit — back the reservation out so a failed attempt
		// doesn't permanently consume the cap.
		if s.spend != nil {
			s.spend.Release(ticket.TicketID)
		}
		s.log.Error("wallet open failed",
			slog.String("endpoint", endpoint),
			opAttr(op),
			relayAttr(hop),
			slog.String("ticket_id", ticket.TicketID),
			slog.Any("err", err))
		// Pool exhaustion (vs a balance shortfall): the wallet HOLDS the ALGO,
		// but every prepaid-pool slot is reserved by an in-flight ticket, so
		// open() reverted 'insufficient MBR deposit' / 'no MBR deposit'. That's a
		// transient concurrency cap, not an unfunded wallet — surface a 429 that
		// points at the knob (raise zs.concurrent_slots) rather than a
		// misleading "fund me" 402 or an opaque 502. Self-heals as in-flight
		// tickets settle, so a retry-after nudge is honest.
		if isPoolExhaustedOpenError(err) {
			e := newError("mbr_pool_exhausted",
				fmt.Sprintf("zerosignal wallet %s has all concurrent ticket slots in use by in-flight requests on %s — "+
					"raise zs.concurrent_slots (run `zs-proxy slots <n>`, which also funds the pool), or retry once in-flight requests settle.",
					s.cfg.PayerAddr, s.cfg.Network))
			e.RetryAfter = 2 * time.Second
			writeError(w, e)
			return
		}
		// Prepaid MBR pool can't be funded: the payer holds USDC but is short on
		// ALGO to grow the ticket-MBR pool (and has no free slot to serve on).
		// This is specifically an ALGO shortfall, NOT a USDC/"unfunded wallet"
		// problem — surface the sentinel's precise µALGO breakdown and say
		// "ALGO", so the owner doesn't go looking at USDC. Distinct code from
		// wallet_unfunded (which reads as the USDC/onboarding case) and from the
		// transient 429 mbr_pool_exhausted. Checked before isUnderfundedOpenError
		// so the actionable detail isn't swallowed by the generic branch.
		// ErrDepositBelowTarget lands here too: a partial (free-quota-box-only)
		// deposit that left the pool short of the working set AND with no free
		// slot to serve on is the same actionable condition — the wallet needs
		// more ALGO — and its message names the remaining shortfall the same way.
		if errors.Is(err, hayai.ErrDepositUnaffordable) || errors.Is(err, hayai.ErrDepositBelowTarget) {
			writeError(w, newError("mbr_pool_underfunded",
				fmt.Sprintf("zerosignal wallet %s needs more ALGO (not USDC) to fund the prepaid ticket-MBR pool on %s — %v. "+
					"Add ALGO with `zs-proxy fund`.", s.cfg.PayerAddr, s.cfg.Network, err)))
			return
		}
		// "Always up, tells you what it needs": an open that fails because the
		// payer can't cover ALGO fees / locked USDC (or isn't USDC-opted-in)
		// surfaces an actionable 402 with the deposit address, not a generic 502.
		// The daemon binds unfunded (the escrow-config read simulates from the
		// fee sink), so this is the path an unfunded wallet hits per request.
		if isUnderfundedOpenError(err) {
			// The web app is offered only on mainnet: the hosted client is built for
			// one network, so a testnet payer sent there would fund the wrong chain.
			hint := "run `zs-proxy fund`."
			if s.cfg.Network == "mainnet" && s.cfg.FundingURL != "" {
				hint = "add funds in the web app (" + s.cfg.FundingURL + ") if this is your web account, " +
					"or run `zs-proxy fund` for a deposit address."
			}
			writeError(w, newError("wallet_unfunded",
				fmt.Sprintf("zerosignal wallet %s can't pay for this request on %s — %s",
					s.cfg.PayerAddr, s.cfg.Network, hint)))
			return
		}
		writeError(w, newError("wallet_open", "payment group could not be submitted"))
		return
	}
	// Open committed: the reservation stays on the tally (settlement reconciles
	// the actual charge lower on-chain; the cap intentionally counts the ceiling).
	// Arm the refund watchdog now that USDC is locked on-chain: if no
	// settlement resolves this ticket (the node burns it on a
	// payment-verification failure, the response never arrives, the operator
	// dies before settling), refundInactive recovers the escrow after
	// expires_at + grace. Resolved on a finalized atomic settle / protest in
	// runReceiptChecks; a box the operator settled standalone is a cheap
	// existence-probe no-op at fire time.
	s.refunds.Track(openHandle, ticket.ExpiresAt)
	txID := openHandle.AppCallTxID
	s.log.Debug("wallet open submitted",
		slog.String("endpoint", endpoint),
		opAttr(op),
		relayAttr(hop),
		slog.String("ticket_id", ticket.TicketID),
		slog.String("app_call_txid", openHandle.AppCallTxID),
		slog.String("group_id", openHandle.GroupID))
	// Compute the admission tag against K_response (unwrapped at reserve
	// time). This is the proof-of-possession the node verifies before
	// Consume — without it, a mempool-race attacker who scraped the
	// ticket_id off-chain could burn the slot. See proto/admission.go and
	// proto/docs/admission-tag.md.
	admissionTag := wire.ComputeAdmissionTag(rt.ResponseKey, ticket.TicketID, txID, body)

	timer := cryptoTimerFrom(ctx)
	t0 := time.Now()
	// Reuse the age identity generated at reserve time as the envelope's
	// reply-to — so the same private half unwraps both the reserve's
	// wrapped_response_key and the response's X-Zs-Response-Key.
	ephemeral := rt.AgeIdentity
	// -debug-bodies escape hatch: dump the exact plaintext we're about to
	// seal (== what the node decrypts and forwards upstream). No-op unless
	// the flag is on. See debug.go.
	s.debugDumpRequestBody(endpoint, op.ID, ticket.TicketID, body)
	// Seal to the recipient PINNED at reserve time (rt.SealRecipient) — the
	// operator's signed ephemeral recipient (mandatory forward secrecy; there is
	// no anchor). The node committed K_response against the key it could open at
	// reserve; a mid-flight registry refresh could rotate the operator's
	// ephemeral between reserve and inference, so reusing the pinned recipient
	// keeps both legs on the exact key the node can decrypt. Always non-nil on a
	// successful Reserve; a nil pin would surface as a clean WrapRequestWithIdentity
	// error below rather than sealing to nothing.
	sealRecipient := rt.SealRecipient
	envelopeJSON, err := wire.WrapRequestWithIdentity(body, txID, ticket.TicketID, admissionTag, ephemeral, sealRecipient)
	timer.recordEncrypt(time.Since(t0))
	if err != nil {
		s.log.Error("wrap request failed",
			slog.String("endpoint", endpoint),
			opAttr(op),
			relayAttr(hop),
			slog.Any("err", err))
		writeError(w, newError("wrap_request", "request could not be wrapped"))
		return
	}
	defer wire.ZeroEphemeralIdentity(ephemeral)

	// Upcast to settlementHandle once so the builders share a single
	// typed reference to the open handle. Fee value pulled off the
	// concrete handle here (the interface is intentionally narrow —
	// it only exposes the dispute/settle surface).
	var sh settlementHandle = openHandle
	openFees := openHandle.OpenFeesMicroalgos
	nonStreamRespond := s.buildHayaiNonStreamResponder(ctx, ephemeral, txID, ticket, op, sh, timer, endpoint, model, algoUSDPrice, openFees, hop, format)

	// Transport-privacy routing. With no hop, send directly to the target
	// (fwdBaseURL = op.BaseURL, fwdEndpoint = endpoint, no extra headers) —
	// byte-identical to pre-relay behavior. With a hop, send the sealed
	// envelope to the relay's RelayPath and carry the inner request via the
	// X-Zs-Relay-* headers (reusing the forwarders' extraHeaders slot). The
	// envelope stays sealed to the target's age key — the relay forwards
	// ciphertext, never decrypts.
	fwdBaseURL, fwdEndpoint := op.BaseURL, endpoint
	var fwdHeaders http.Header
	if hop != nil {
		rr := protorelay.BuildRequest(hop.BaseURL, hop.TargetID, hop.TargetNodeID, endpoint, http.MethodPost)
		fwdBaseURL, fwdEndpoint = rr.URL, ""
		fwdHeaders = http.Header{}
		fwdHeaders.Set(wire.RelayTargetHeader, rr.Target)
		fwdHeaders.Set(wire.RelayTargetNodeHeader, rr.TargetNode)
		fwdHeaders.Set(wire.RelayPathHeader, rr.Path)
		fwdHeaders.Set(wire.RelayMethodHeader, rr.Method)
	}

	if wantsStream {
		// genComplete flips true when the frame factory decrypts a
		// generation-terminal frame (chat finish_reason stop/length, or a
		// /v1/responses terminal event). forwardRawStream consults it on a
		// client disconnect to decide whether to drain the receipt/settle tail
		// (node already done → pay the operator for delivered content) or
		// cancel the upstream (still generating → abandoned request).
		var genComplete atomic.Bool
		// Opt-in: only emit the non-OpenAI `event: zs.usage` frame when the
		// client asked for it (hayai-aware: ui/, tui/). Default off keeps the
		// stream a clean OpenAI stream for strict clients (JetBrains/Koog).
		emitUsageFrame := strings.TrimSpace(r.Header.Get(hayaiUsageFrameHeader)) != ""
		factory := s.buildHayaiFrameFactory(ctx, ephemeral, txID, ticket, op, sh, timer, endpoint, model, algoUSDPrice, openFees, hop, &genComplete, emitUsageFrame, format)
		s.forwardRawStream(ctx, w, r, fwdBaseURL, fwdEndpoint, envelopeJSON, wire.EncryptedContentType, fwdHeaders, hop, factory, nonStreamRespond, &genComplete)
		return
	}
	s.forwardRawNonStream(ctx, w, r, fwdBaseURL, fwdEndpoint, envelopeJSON, wire.EncryptedContentType, fwdHeaders, hop, nonStreamRespond)
}

// resolveUsePrivacy applies a per-request relay preference on top of the proxy
// config. relayPref is the normalized caller preference (selection.RelayAuto /
// RelayOff / RelayRequired, or "" for none):
//
//   - RelayRequired → always true (force a relay; can only strengthen privacy,
//     so it's never gated by allowOverride).
//   - RelayOff      → false only when allowOverride is set; otherwise the
//     config default stands (the caller's weakening request is refused).
//   - RelayAuto / "" → the config default (configPrivacy).
//
// Pure for testability; the caller logs the refused-override case.
func resolveUsePrivacy(configPrivacy, allowOverride bool, relayPref string) bool {
	switch relayPref {
	case selection.RelayRequired:
		return true
	case selection.RelayOff:
		if allowOverride {
			return false
		}
	}
	return configPrivacy
}

// relayHopFor selects the transport-privacy relay hop for target. usePrivacy is
// the per-request decision resolved in dispatchHayai (config default, possibly
// overridden by provider.relay / X-Zs-Relay) — NOT Config.Privacy
// directly, so a caller's relay:off / relay:required is honored. It returns
// (nil, nil) when privacy is off — the caller then sends directly to the
// target, byte-identical to pre-relay behavior. When privacy is on it returns
// the chosen relay hop, or (nil, selection.ErrNoRelay) when no operator
// qualifies; the caller MUST NOT fall back to a direct route in that case.
func (s *Server) relayHopFor(ctx context.Context, target hayai.Operator, usePrivacy bool) (*hayai.RelayHop, error) {
	if !usePrivacy {
		return nil, nil
	}
	return s.relayHopForPool(s.relayPool(ctx), target, usePrivacy)
}

// relayPool projects the current registry into the relay-candidate set consumed
// by SelectRelayHopWeighted: one selection.Operator per node, with a soft
// downrank applied to any relay carrying a forward-failure streak (it drops to
// SelectRelay's fallback tier, never hard-excluded, so the cold-start fallback
// holds). This projection is target-INDEPENDENT, so dispatchHayai builds it once
// per request and threads it into every per-candidate relayHopForPool — the
// reserve loop no longer rebuilds the whole-fleet projection on each candidate it
// tries (was O(n)·candidates, now O(n) once).
//
// Consequence of building it once: the RelayDownranked bit is captured at
// projection time, so a relay that crosses the downrank threshold *mid-sweep*
// (from an earlier candidate's failed forward) is not demoted for later
// candidates in that same sweep. That's an accepted tradeoff — the downrank is
// a soft preference, not an exclusion, and it takes 3 strikes on one relay
// within a single short loop (unlikely given per-candidate random rotation) to
// trigger at all. It is bounded to ONE sweep, though: dispatchHayai re-projects
// between sweeps, so a relay proven dead early doesn't ride the full 60s window
// at full weight. The latency weighting is NOT frozen even within a sweep —
// relayHopForPool's latencyOf reads the live store per candidate.
func (s *Server) relayPool(ctx context.Context) []selection.Operator {
	all := s.registryProvider.AllOperators(ctx)
	sel := make([]selection.Operator, 0, len(all))
	for _, op := range all {
		// Proven-malicious node: a true DROP, not RelayDownranked's soft demote to
		// the fallback tier. A node that tried to take the payer's account or
		// overcharge is not trusted to forward traffic either (see
		// malicious_nodes.go).
		if s.nodeExcluder != nil && s.nodeExcluder.NodeExcluded(hayai.RefOf(op)) {
			continue
		}
		m := op.Selection()
		if s.relayRep != nil && s.relayRep.RelayDownranked(hayai.RefOf(op)) {
			m.Reachable = false
		}
		sel = append(sel, m)
	}
	return sel
}

// relayHopForPool picks a relay hop for target from a pre-built pool (see
// relayPool). Only the latency weighting and the target-exclusion inside
// SelectRelayHopWeighted are target-dependent, so a caller iterating many
// candidates reuses one pool across all of them.
func (s *Server) relayHopForPool(sel []selection.Operator, target hayai.Operator, usePrivacy bool) (*hayai.RelayHop, error) {
	if !usePrivacy {
		return nil, nil
	}
	// Weight the rotation toward relays that are fast FOR THIS target (the full
	// browser→relay→target path when measured, else the relay endpoint), while
	// still spreading (anti-profiling). Cold/unknown relays keep being sampled,
	// and an all-cold pool degrades to the plain seed rotation — identical to
	// before until latency data warms. No-op latencyOf when relayLatency is nil.
	targetRef := hayai.RefOf(target)
	latencyOf := func(relay hayai.NodeRef) (float64, bool) {
		if s.relayLatency == nil {
			return 0, false
		}
		return s.relayLatency.RelayLatencyForTarget(relay, targetRef)
	}
	return hayai.SelectRelayHopWeighted(sel, target.Selection(), hayai.RandomRelaySeed(), latencyOf)
}

// recordRelayOutcome reports the outcome of a forward through hop to the
// per-relay reputation store. A nil hop (direct route) or nil store is a
// no-op. ok=false on a relay-hop failure (transport error reaching the relay,
// or a relay-generated hop error) deprioritizes the relay; ok=true clears its
// failure streak.
func (s *Server) recordRelayOutcome(hop *hayai.RelayHop, ok bool) {
	if hop == nil || s.relayRep == nil {
		return
	}
	s.relayRep.RecordRelayOutcome(hop.RelayRef(), ok)
}

// relayEvidence assembles the caller-held facts transient.NarrowRelayed needs
// about a relayed forward — facts the body could not carry: that we relayed at
// all, that the relay stamped wire.RelayHopHeader, that it advertises a
// generation where the header's ABSENCE means something, and whether the
// failure was our own doing.
//
// A nil header (no response arrived) reads as "no marker", which is correct and
// harmless: NarrowRelayed's transport-failure rule fires first and never
// consults it. The version gate reads the hop's ADVERTISED version, which
// buildSelAll deliberately seeds as wire.BootstrapProtoVersion() for an
// unprobed peer so a node we have never heard from can never owe us a header.
//
// ctx is the context the request actually rode, and it answers CallerAborted.
// It has to be asked, because a payer hanging up mid-generation surfaces as the
// same transient.TransportFailureStatus as a dial failure to a dead relay —
// NarrowRelayed's rule 3 would then charge the relay for a socket we tore down
// ourselves. The non-streaming forward is where that bites: it rides the
// payer's own r.Context() and blocks for the whole generation.
//
// Deliberately NARROWER than transient_retry.go's callerAborted, which also
// treats any net.Error timeout as ours. That leg's client carries a 5s
// DefaultReserveTimeout, so a timeout there really is our deadline; the forward
// client sets Client.Timeout 0 (server.go), so its timeouts are dial, TLS
// handshake, or the httpx.ForwardHeaderBackstop — the first two the relay's own
// fault. Known residue: the 5-minute header backstop firing while a relay sits
// byte-silent waiting on a slow target (image/video generation) still charges
// the relay, the client-side twin of the 504/524 case NarrowRelayed abstains
// on. Separating it from a dial timeout needs an httptrace GotConn hook on the
// forward hot path; not worth it until the strikes are observed.
//
// ctx.Err() != nil is also exactly the TS predicate (envelope-fetch.ts passes
// init.signal?.aborted on its inference leg). Keep the two in step — charging
// different hops for the same outcome is the drift this evidence struct exists
// to prevent.
func relayEvidence(ctx context.Context, hop *hayai.RelayHop, header http.Header) transient.RelayEvidence {
	if hop == nil {
		return transient.RelayEvidence{}
	}
	return transient.RelayEvidence{
		Relayed:        true,
		HopMarker:      header.Get(wire.RelayHopHeader) != "",
		RelayMarksHops: wire.SetsRelayHopHeader(hop.RelayProtoVersion),
		CallerAborted:  ctx != nil && ctx.Err() != nil,
	}
}

// attributeRelayHop is the single entry point for charging a forward through
// hop, via the shared transient verdict (Classify, then NarrowRelayed over the
// route evidence) so the proxy and the client/ app charge the same hop for the
// same outcome. Both seams go through it — a response that arrived, and a
// transport failure that produced none (statusCode
// transient.TransportFailureStatus, nil header and body). The two used to
// diverge: the transport seams hand-rolled "transport error ⇒ relay fault"
// against the reputation store directly, which reached neither Classify nor
// NarrowRelayed and so could not see a caller abort:
//   - transient.AttrRelay means the relay itself failed and it's deprioritized.
//     Three ways to land here: a relay-generated hop error (relay_busy /
//     relay_unknown_target / relay_bad_*), a transport failure (the socket we
//     opened was the relay's), or — since 9.1 — a code-less transient status
//     from a relay that advertises the hop marker and did not stamp it, which
//     proves its own front door answered and its handler never ran.
//     It is a reputation charge, not leave to resend after escrow.open: a
//     transport failure lands here even when the relay had already forwarded.
//     transient.RetryableAfterPayment decides that, from the code.
//   - transient.AttrTarget is the relay's *claim* about the target: either
//     relay_upstream_unreachable, or a marked code-less transient status ("I
//     forwarded, and this is what I got"). Believing either at face value would
//     let a non-compliant fork black-hole every forward and never accrue a
//     streak, so both go through RecordRelayUpstreamUnreachable, which
//     penalizes the relay only when our own probes contradict the claim.
//   - transient.AttrUnknown is what survives when the route evidence still
//     can't decide — in practice a code-less status from a pre-9.1 relay, or an
//     UNMARKED gateway timeout, which NarrowRelayed abstains on at every
//     version. Note the qualifier: a MARKED timeout is rule 5's business and
//     lands on AttrTarget above, which is correct — the marker proves the relay
//     ran its handler, so the timeout is its target's. It attributes NOTHING:
//     both a credit and a penalty would be a guess.
//     Crediting was the old behavior and the more damaging one, since it let a
//     relay behind a broken CDN keep a spotless streak while dropping every
//     forward. For the code-less residue the reserve loop's rotation
//     differential (reserveWithTransientRetry) is what establishes blame; for
//     the timeout slice — which the reserve leg cannot see, because a reserve
//     round-trip is far too short to trip a front door's idle timer — the
//     separate, higher-threshold RecordRelayForwardTimeout streak is.
//   - Anything else (a recognized node code, or a sealed/forwarded target
//     response) means the relay did its job — credit it.
//
// No-op for a direct route (nil hop) or when reputation is disabled.
func (s *Server) attributeRelayHop(ctx context.Context, hop *hayai.RelayHop, statusCode int, header http.Header, body []byte) {
	if hop == nil || s.relayRep == nil {
		return
	}
	if statusCode == transient.TransportFailureStatus || statusCode >= 400 {
		raw := transient.Classify(statusCode, openAIErrorCode(body))
		ev := relayEvidence(ctx, hop, header)
		v := transient.NarrowRelayed(raw, statusCode, ev)
		switch v.Attribution {
		case transient.AttrRelay:
			s.relayRep.RecordRelayOutcome(hop.RelayRef(), false)
			return
		case transient.AttrTarget:
			// Two very different strengths of evidence land here, and they get
			// different differentials. An explicit relay_upstream_unreachable
			// (raw already AttrTarget) is a CLAIM the relay chose to make, so
			// it is validated both ways — right or wrong. A merely MARKED
			// code-less status (only AttrTarget after narrowing) asserts
			// nothing beyond "my handler ran", so it is penalty-only: crediting
			// on it would let every target restart wipe a half-broken relay's
			// streak and hold it under the threshold forever.
			if raw.Attribution == transient.AttrTarget {
				s.relayRep.RecordRelayUpstreamUnreachable(hop.RelayRef(), hop.TargetRef())
			} else {
				s.relayRep.RecordRelayForwardedTargetFault(hop.RelayRef(), hop.TargetRef())
			}
			return
		case transient.AttrUnknown:
			// Still records nothing about *fault* — the verdict genuinely can't
			// decide, and both a credit and a penalty would be a guess.
			//
			// One narrow slice of it does get remembered, though, because leaving
			// it entirely unremembered is what made a CDN-fronted relay a
			// permanent trap: an unattributed TIMEOUT costs the relay nothing, so
			// routing keeps picking the relay that kills every forward it can't
			// answer in time. Reaching here with a timeout status means the
			// request was relayed, we did not abort it ourselves (rule 2), it was
			// not a transport failure (rule 3 would have said AttrRelay), and the
			// response carried no hop marker — so the only remaining readings are
			// "this relay's front door gave up" and "the target was slow".
			// RecordRelayForwardTimeout keeps the two apart the only way a single
			// request cannot: differentially, over repetition, at its own higher
			// threshold. It is not an attribution, which is why it does not touch
			// the failure streak and never credits.
			//
			// Two limits worth knowing rather than rediscovering. The marker gate
			// means a 9.1+ relay lands here ONLY for its own front door (a
			// forwarded target timeout is marked, so it took AttrTarget above),
			// while a pre-9.1 or never-probed relay lands here for both — so the
			// honest-accrual risk is concentrated on un-upgraded relays, not
			// spread evenly. And this is not buffered-only: sse.go reaches here on
			// the non-SSE fallback, so a STREAMING request whose relay gave up
			// before the target's headers arrived feeds it too. The node's
			// keepalive only starts once those headers exist.
			if steering.IsForwardTimeoutStatus(statusCode) && !ev.CallerAborted {
				s.relayRep.RecordRelayForwardTimeout(hop.RelayRef(), hop.TargetRef())
			}
			return
		}
		// AttrNone reaches here only from a Classify that recognized an error
		// code, i.e. a real response the relay carried for us — so falling
		// through to the credit is right for a response, and never right for a
		// transport failure where nothing arrived to credit. The seams pass a nil
		// body, so Classify answers AttrUnknown and this is unreachable today;
		// the guard is structural because the alternative is a credit branch
		// standing one plausible edit away from crediting a relay we never
		// reached.
		if statusCode == transient.TransportFailureStatus {
			return
		}
	}
	s.relayRep.RecordRelayOutcome(hop.RelayRef(), true)
}

// opAttr returns the (operator_id, node_id) pair identifying the target node a
// request is dispatched to. Routing keys on the *pair* (operator/node split —
// see the repo AGENTS.md), so both ids belong on every log line that names a
// target; emitting them through one helper keeps them from drifting apart the
// way 23 hand-written `operator_id`-only sites once did. The two keys are
// emitted flat (slog inlines an empty-key group), so a line reads
// `operator_id=1 node_id=3`, pairing with relayAttr on the same line.
func opAttr(op hayai.Operator) slog.Attr {
	return slog.Group("",
		slog.Uint64("operator_id", op.ID),
		slog.Uint64("node_id", op.NodeID))
}

// relayAttr returns the (operator_id, node_id) pair naming the relay an outbound
// request was tunneled through in transport-privacy mode, for pairing with the
// target's opAttr on the same line (read as "target operator/node, via this
// relay operator/node"). A relay is itself a single node, so it gets the same
// pair as any routing target. The ids are emitted flat as relay_operator_id +
// relay_node_id (slog inlines an empty-key group). A nil hop — privacy off, i.e.
// a direct route — yields the zero Attr, which slog's handlers drop, so
// direct-routed requests log no relay_* keys at all. Safe to drop into any
// LogAttrs slice or variadic log call unconditionally.
func relayAttr(hop *hayai.RelayHop) slog.Attr {
	if hop == nil {
		return slog.Attr{}
	}
	return slog.Group("",
		slog.Uint64("relay_operator_id", hop.RelayID),
		slog.Uint64("relay_node_id", hop.RelayNodeID))
}

// buildHayaiNonStreamResponder decrypts the node's non-streaming response,
// verifies commit_k, and — on success — records any tool_call ids in the
// affinity cache so the next turn of a tool-calling conversation routes
// back to the same operator.
func (s *Server) buildHayaiNonStreamResponder(
	ctx context.Context,
	ephemeral *age.X25519Identity,
	txID string,
	ticket *ticket.Ticket,
	op hayai.Operator,
	handle settlementHandle,
	timer *cryptoTimer,
	endpoint, model string,
	algoUSDPrice float64,
	openFees uint64,
	hop *hayai.RelayHop,
	format clientFormat,
) nonStreamResponder {
	return func(w http.ResponseWriter, upstreamResp *http.Response, respBody []byte) error {
		// Captured before the first copyResponseHeaders: the X-Zs-* the proxy
		// itself set earlier in dispatch (the max_output clamp marker) would
		// otherwise be deleted along with the node's by stripHayaiHeaders. The
		// streaming path never strips, so this is the only place it can be lost.
		proxyHdrs := snapshotHayaiHeaders(w.Header())
		wrappedKey := upstreamResp.Header.Get(wire.ResponseKeyHeader)
		ct := upstreamResp.Header.Get("Content-Type")
		if wrappedKey == "" {
			// The node only omits the response key for transport-level
			// errors written before sealing is set up (writeOpenAIError
			// — bad envelope, ticket failures; SPEC §10). A 2xx response
			// without a sealed key is a protocol violation: the operator
			// would be serving plaintext data through an admitted ticket.
			// Refuse so a misbehaving operator can't silently ship
			// unencrypted output.
			if upstreamResp.StatusCode < 400 {
				s.log.Warn("operator returned non-error response without sealed key — protocol violation",
					opAttr(op),
					relayAttr(hop),
					slog.Int("upstream_status", upstreamResp.StatusCode))
				writeOpenAIError(w, http.StatusBadGateway, "proxy_error", "operator_unsealed_response",
					"operator returned a response without sealing it")
				return nil
			}
			// Transport-level error from the node (status >= 400,
			// plaintext OpenAI-shaped JSON). Pass through so the client
			// can see the cause (ticket_required, ticket_invalid, etc.).
			// Also surface it in our own log (default-on WARN) — pre-envelope
			// errors are plaintext control-plane, never completion content.
			msg, openAIShaped := responseErrorMessage(respBody)
			if !openAIShaped {
				// Not an OpenAI-shaped error, so it did not come from a node at
				// all — in practice an operator's CDN / ingress / LB error page
				// (a bunny.net HTML 504 when it can't reach its origin). Passing
				// that through hands an OpenAI client an unparseable body: a
				// strict SSE client reports only "expected 200, got 504" and a
				// JSON-decoding one fails on "<". Replace it with a structured
				// error and keep the status, which is the real signal.
				//
				// The synthesized body carries NO error.code on purpose. A
				// code-less 5xx is precisely how transient.Classify recognizes
				// out-of-tree infrastructure as retryable; inventing a code here
				// would flip a retryable gateway blip into a terminal refusal for
				// any caller that classifies our response.
				// Content-Type is operator-controlled and unbounded (net/http allows
				// ~10MB of response headers), and it lands in both the payer's log
				// and the client-visible message — truncate like every other
				// untrusted-upstream string.
				ctSafe := truncateForLog(ct, 64)
				s.log.Warn("operator returned a non-OpenAI error body; replacing it with a structured error",
					opAttr(op), relayAttr(hop),
					slog.Int("upstream_status", upstreamResp.StatusCode),
					slog.String("content_type", ctSafe),
					slog.Int("body_bytes", len(respBody)))
				// Preserve Retry-After before writing our own body. An edge rate
				// limiter (Cloudflare, nginx limit_req) answers 429/503 with an HTML
				// page, which lands here — dropping its hint would make the client
				// retry blind. writeOpenAIError Sets Content-Type, so it still wins.
				copyResponseHeaders(w.Header(), upstreamResp.Header)
				stripNodeHayaiHeaders(w.Header(), proxyHdrs)
				w.Header().Del("Content-Length")
				// Deliberately NOT claiming which layer answered. The proxy cannot
				// tell an operator's CDN from the node's own mux — Go's ServeMux
				// answers an unregistered route with a text/plain "404 page not
				// found", so asserting "the front door answered, not its node" would
				// be a positive falsehood on exactly that case.
				//
				// No error.code, on purpose: a code-less 5xx is how
				// transient.Classify recognizes out-of-tree infrastructure as
				// retryable, and inventing one would flip a recoverable gateway blip
				// into a terminal refusal for any caller that classifies our response.
				writeOpenAIError(w, upstreamResp.StatusCode, "server_error", "",
					fmt.Sprintf("operator returned HTTP %d with a body this proxy could not parse as an OpenAI error (content-type %q)",
						upstreamResp.StatusCode, ctSafe))
				return nil
			}
			s.log.Warn("operator returned pre-envelope error",
				opAttr(op), relayAttr(hop),
				slog.Int("upstream_status", upstreamResp.StatusCode),
				slog.String("error", msg))
			copyResponseHeaders(w.Header(), upstreamResp.Header)
			// Same §5.2-step-4 hygiene as the sealed success path: even on a
			// pre-envelope error, no node-set X-Zs-* header reaches the
			// client (a hostile node could stuff arbitrary values here).
			stripNodeHayaiHeaders(w.Header(), proxyHdrs)
			w.Header().Del("Content-Length")
			w.WriteHeader(upstreamResp.StatusCode)
			_, _ = w.Write(respBody)
			return nil
		}

		// Response key was set — body must be sealed.
		if !strings.HasPrefix(ct, wire.EncryptedContentType) {
			s.log.Warn("operator set response key but returned non-envelope content-type — protocol violation",
				opAttr(op),
				relayAttr(hop),
				slog.String("content_type", ct))
			writeOpenAIError(w, http.StatusBadGateway, "proxy_error", "operator_inconsistent_response",
				"operator returned a response key but did not seal the body")
			return nil
		}

		t0 := time.Now()
		responseKey, err := wire.UnwrapResponseKey(wrappedKey, ephemeral)
		timer.recordDecrypt(time.Since(t0))
		if err != nil {
			return fmt.Errorf("unwrap response key: %w", err)
		}

		if err := verifyCommitK(ticket, responseKey); err != nil {
			return err
		}

		// One opener for the whole response: it names the (txID, ticketID)
		// binding once, so the body and the two sealed headers below cannot
		// disagree about what they were sealed under.
		opener, err := wire.NewResponseOpener(responseKey, txID, ticket.TicketID)
		if err != nil {
			return fmt.Errorf("build response opener: %w", err)
		}

		t1 := time.Now()
		plaintext, err := opener.OpenBody(respBody)
		timer.recordDecrypt(time.Since(t1))
		if err != nil {
			return fmt.Errorf("decrypt body: %w", err)
		}

		// Surface an operator/upstream error body (default-on WARN). Sealed
		// post-admit errors (provider rejections, etc.) arrive here decrypted;
		// logging the error envelope keeps a failed request diagnosable on the
		// payer's own process without -debug-bodies. Not completion content.
		if msg, ok := responseErrorMessage(plaintext); ok {
			s.log.Warn("operator returned error",
				opAttr(op), relayAttr(hop),
				slog.String("ticket_id", ticket.TicketID),
				slog.String("error", msg))
		}

		// Receipt verification. The node attaches a signed UsageReceipt
		// on every admitted response; absence of the header (e.g. node
		// on an older version) is logged but not fatal. Presence +
		// verification failure is evidence of operator misbehaviour
		// and (step 8) drives escrow.protest.
		receiptHdr := openSealedResponseMeta(s, upstreamResp.Header.Get(wire.ReceiptHeader), opener, ticket, wire.SealedHeaderReceipt, op, hop)
		settleGroupHdr := openSealedResponseMeta(s, upstreamResp.Header.Get(wire.SettleGroupHeader), opener, ticket, wire.SealedHeaderSettleGroup, op, hop)
		receipt, submitSettle := s.verifyNonStreamReceipt(ctx, receiptHdr, settleGroupHdr, endpoint, model, ticket, op, handle, plaintext, algoUSDPrice, hop)
		// The escrow submit is launched asynchronously so the handler never
		// blocks the client's response on an algod round-trip. The price is the
		// fee headers below: they cannot include the payer's settle fee, which is
		// known only once the submit returns. On the atomic path that fee is 0 by
		// construction (the settle-group verifier refuses a non-zero payer fee);
		// only the standalone-ack fallback pays one, and the submit logs it.
		defer s.submitAfterResponse(ticket.TicketID, submitSettle)
		const settleFees = 0

		// Record tool-call ids for affinity. Harmless if the response has
		// none (most don't).
		if s.toolAffinity != nil {
			if ids := hayai.ExtractResponseToolCallIDs(plaintext); len(ids) > 0 {
				s.toolAffinity.Record(op.ID, op.NodeID, ids)
			}
		}
		// Record response_id for /v1/responses session pinning. The
		// next turn carrying previous_response_id will route back to
		// this same node (strict, regardless of affinity_policy — see
		// resolveResponseIDPin for why).
		if s.responseAffinity != nil && endpoint == endpointResponses {
			if id := hayai.ExtractResponseID(plaintext); id != "" {
				s.responseAffinity.Record(op.ID, op.NodeID, []string{id})
			}
		}

		// -debug-bodies escape hatch: dump the decrypted response we're about
		// to return (symmetric with the request dump in runHayaiSealed). No-op
		// unless the flag is on. See debug.go.
		s.debugDumpResponseBody(endpoint, op.ID, ticket.TicketID, plaintext)

		copyResponseHeaders(w.Header(), upstreamResp.Header)
		// SPEC §5.2 step 4: no node-set X-Zs-* header reaches the client —
		// not just the response key and receipt, but X-Zs-Settle-Group and
		// anything a future node adds. setHayaiUsageHeaders re-adds the
		// proxy-owned usage headers below.
		stripNodeHayaiHeaders(w.Header(), proxyHdrs)
		w.Header().Del("Content-Length")
		w.Header().Set("Content-Type", "application/json")
		if receipt != nil {
			// Payer-facing fee breakdown from the proxy payer's cached
			// protocolFeeBps (background-refreshed via a direct global read —
			// never blocks this path). ok==false degrades to no breakdown.
			feeBps, haveFee := s.feeRateNow()
			setHayaiUsageHeaders(w.Header(), receipt, ticket, op, openFees, settleFees, algoUSDPrice, feeBps, retiredDiscountBps, haveFee)
		}
		// Legacy /v1/completions emulation: reshape the verified chat-completion
		// body into text-completion shape for the client. Done AFTER receipt /
		// body_hash verification (which must run on the node's original chat
		// bytes) and only to the bytes written out. No-op for formatChat, and a
		// pass-through for anything that isn't a chat completion (sealed errors).
		out := plaintext
		if format == formatLegacyCompletions {
			out = completionsResponseFromChat(plaintext)
		}
		w.WriteHeader(upstreamResp.StatusCode)
		_, _ = w.Write(out)
		return nil
	}
}

// inferenceDenom returns the (currency, decimals) tuple the inference
// charge is denominated in for the given ticket. The contract escrows
// USDC (SPEC.md §3.3a), so the ticket's microUSDC amounts are reported
// as ("USDC", 6). Kept as a function (rather than a constant) so a
// future Ticket-level currency field — or a per-operator override —
// can plug in without renaming any header/SSE event field.
func inferenceDenom(_ *ticket.Ticket) (currency string, decimals int) {
	return "USDC", 6
}

// setHayaiUsageHeaders surfaces the node's signed usage receipt plus
// the on-chain network fees the *payer* (this proxy) paid for the
// request as plain response headers, so a non-streaming client can see
// what the request cost in inference + fees. The settle fee is known
// only after the settle submit, which runs after the response is
// written, so the non-streaming caller passes 0 for it: exact on the
// atomic settle path (the payer's fee there is 0), an undercount on the
// standalone-ack fallback. Stream clients don't get these (HTTP headers
// are fixed at stream start) — they get a synthetic `zs.usage` SSE
// frame instead, which does include the settle fee.
//
// Operator-paid fees (the gtxn[1] open over-fee and the gtxn[0]
// settle over-fee that pool the rest of each group via Algorand fee
// pooling) are deliberately excluded — reporting them as "ALGO fees"
// would mislead the user about what they paid.
//
// Inference is denominated in USDC (the contract escrows USDC, see
// SPEC.md §3.3a); network fees stay in ALGO regardless. The two USD
// conversions are independent: inference USD comes straight from the
// USDC amount (1 USDC ≈ $1), fee USD requires the ALGO/USD rate.
func setHayaiUsageHeaders(h http.Header, r *ticket.UsageReceipt, ticket *ticket.Ticket, op hayai.Operator, openFees, settleFees uint64, algoUSDPrice float64, feeBps, discountBps uint64, haveFee bool) {
	currency, decimals := inferenceDenom(ticket)
	totalFees := openFees + settleFees

	h.Set("X-Zs-Ticket-Id", r.TicketID)
	if op.ID != 0 {
		h.Set("X-Zs-Operator-Id", strconv.FormatUint(op.ID, 10))
	}
	// Node id within the operator (operator/node split): the (operator, node)
	// pair identifies the serving node. Node ids are 1-based on-chain, so 0 is
	// the unset sentinel and the header is simply omitted then.
	if op.NodeID != 0 {
		h.Set("X-Zs-Node-Id", strconv.FormatUint(op.NodeID, 10))
	}
	if op.OwnerAddr != "" {
		h.Set("X-Zs-Operator-Owner-Addr", op.OwnerAddr)
	}
	h.Set("X-Zs-Actual-Input-Count", strconv.FormatUint(r.ActualInputCount, 10))
	h.Set("X-Zs-Actual-Output-Count", strconv.FormatUint(r.ActualOutputCount, 10))
	// AmountCharged is the operator's BASE (net) take; under the additive fee
	// model the payer's full USDC debit is base + the protocol fee (netFee).
	// The HAY fee discount is RETIRED, so discountBps is always 0 and
	// netFee == grossFee — a pure function of the signed AmountCharged and the
	// live feeBps, no longer gated on the confirmed settle's treasury
	// inner-transfer. The proxy uses its own payer's rate (cached,
	// background-refreshed via a direct protocolFeeBps global read — feeRateNow).
	// It equals the
	// per-ticket open-time snapshot the contract charges; the on-chain snapshot
	// stays the settlement authority. The X-Zs-{Platform-Fee,
	// Refund,Total-Debit}-Microusdc headers below carry the decomposition.
	// Max-Price (escrowed, grossed up) still bounds it.
	h.Set("X-Zs-Inference-Amount", strconv.FormatUint(r.AmountCharged, 10))
	h.Set("X-Zs-Inference-Currency", currency)
	h.Set("X-Zs-Inference-Decimals", strconv.Itoa(decimals))
	// Escrowed ceiling. Under the additive fee model this is grossed up to
	// cover the operator's base charge PLUS the worst-case protocol fee, so
	// clients MUST NOT derive the payer refund as (max_price − inference_amount)
	// — that overstates it by the fee. The on-chain settlement refunds
	// max_price − amount_charged − netFee; read the actual refund from chain.
	h.Set("X-Zs-Max-Price-Amount", strconv.FormatUint(ticket.MaxPrice, 10))
	// Symmetric with Max-Price: the operator's per-request minimum-charge
	// floor pinned on the ticket (SPEC.md §3a "Minimum charge"). 0 means
	// no floor for this ticket — always emitted so clients can rely on
	// the header's presence rather than detecting absence.
	h.Set("X-Zs-Min-Price-Amount", strconv.FormatUint(ticket.MinPrice, 10))
	h.Set("X-Zs-Fees-Microalgos", strconv.FormatUint(totalFees, 10))
	if r.AmountCharged > 0 {
		h.Set("X-Zs-Inference-Amount-Usd", fmt.Sprintf("$%.6f", inferenceUSD(r.AmountCharged, currency, decimals, algoUSDPrice)))
	}
	if algoUSDPrice > 0 {
		h.Set("X-Zs-Fees-Usd", fmt.Sprintf("$%.6f", float64(totalFees)/1_000_000*algoUSDPrice))
		h.Set("X-Zs-Algo-Usd-Rate", strconv.FormatFloat(algoUSDPrice, 'f', -1, 64))
	}
	// Additive-fee breakdown from the open-time snapshot (only when readable).
	// platform_fee is the payer's protocol fee on top of the operator's base;
	// total_debit = inference + platform_fee is the payer's real USDC cost.
	if fb := feeBreakdownFor(r.AmountCharged, ticket.MaxPrice, feeBps, discountBps, haveFee, currency, decimals); fb != nil {
		h.Set("X-Zs-Fee-Bps", strconv.FormatUint(fb.FeeBps, 10))
		h.Set("X-Zs-Discount-Bps", strconv.FormatUint(fb.DiscountBps, 10))
		h.Set("X-Zs-Platform-Fee-Microusdc", strconv.FormatUint(fb.PlatformFeeMicrousdc, 10))
		h.Set("X-Zs-Refund-Microusdc", strconv.FormatUint(fb.RefundMicrousdc, 10))
		h.Set("X-Zs-Total-Debit-Microusdc", strconv.FormatUint(fb.TotalDebitMicrousdc, 10))
		if fb.TotalDebitUsd > 0 {
			h.Set("X-Zs-Total-Debit-Usd", fmt.Sprintf("$%.6f", fb.TotalDebitUsd))
		}
	}
}

// inferenceUSD converts an inference charge to USD. USDC is dollar-
// pegged so the conversion is the straight 1eN unscale; ALGO requires
// the algoUSDPrice oracle reading and is retained for backwards
// compatibility (returns 0 when the rate is missing rather than
// fabricating one). Unknown currencies return 0.
func inferenceUSD(amount uint64, currency string, decimals int, algoUSDPrice float64) float64 {
	switch currency {
	case "USDC":
		return float64(amount) / pow10(decimals)
	case "ALGO":
		if algoUSDPrice <= 0 {
			return 0
		}
		return float64(amount) / pow10(decimals) * algoUSDPrice
	}
	return 0
}

// pow10 returns 10^n as a float64. Small n only (currency decimals).
func pow10(n int) float64 {
	out := 1.0
	for i := 0; i < n; i++ {
		out *= 10
	}
	return out
}

// hayaiUsageFrameEvent is the SSE event name the proxy emits in place
// of the swallowed signed receipt so streaming clients can display
// per-request usage + cost. It is OPT-IN (hayaiUsageFrameHeader): the
// frame's `data:` payload is not a valid OpenAI chat chunk, and strict
// OpenAI clients that parse every `data:` line rather than dispatching
// on the SSE `event:` type (e.g. JetBrains/Koog) throw on it — so the
// proxy stays a clean drop-in OpenAI endpoint by default and only emits
// the frame for hayai-aware clients that ask for it.
const hayaiUsageFrameEvent = "zs.usage"

// hayaiUsageFrameHeader is the request header a hayai-aware streaming
// client sets (any non-empty value) to opt into receiving the
// `event: zs.usage` SSE frame. Absent → the proxy suppresses the
// frame for OpenAI compatibility. Settlement is unaffected either way —
// it runs when the proxy reads the receipt, before this frame is built.
const hayaiUsageFrameHeader = "X-Zs-Usage-Frame"

// hayaiInferenceCost groups the inference charge with its currency
// designator so a future USDC ticket only flips the Currency value
// (and Decimals if needed) — clients keying off the field names don't
// have to change.
type hayaiInferenceCost struct {
	Amount    uint64  `json:"amount"`
	Currency  string  `json:"currency"`
	Decimals  int     `json:"decimals"`
	AmountUsd float64 `json:"amount_usd,omitempty"`
}

// hayaiUsage is the unsigned client-facing projection of UsageReceipt
// + the proxy's known on-chain network-fee commitment. Sig + BodyHash
// are deliberately omitted (internal audit fields the client cannot
// verify on its own).
type hayaiUsage struct {
	Type       string `json:"type"`
	TicketID   string `json:"ticket_id"`
	OperatorID uint64 `json:"operator_id,omitempty"`
	// NodeID is the serving node within OperatorID (operator/node split). Omitted
	// when zero — node ids are 1-based on-chain (0 is the unset sentinel) — so the
	// pair reads operator_id+node_id together for the node that actually served.
	NodeID            uint64             `json:"node_id,omitempty"`
	OperatorOwnerAddr string             `json:"operator_owner_addr,omitempty"`
	ActualInputCount  uint64             `json:"actual_input_count"`
	ActualOutputCount uint64             `json:"actual_output_count"`
	Inference         hayaiInferenceCost `json:"inference"`
	MaxPriceAmount    uint64             `json:"max_price_amount"`
	// MinPriceAmount mirrors the ticket's min_price (microUSDC) — the
	// per-request floor the operator was committed to (SPEC.md §3a
	// "Minimum charge"). 0 when the floor was disabled at reserve.
	// Omitted when zero so back-compat consumers don't see a new key.
	MinPriceAmount     uint64  `json:"min_price_amount,omitempty"`
	AlgoFeesMicroalgos uint64  `json:"algo_fees_microalgos"`
	AlgoFeesUsd        float64 `json:"algo_fees_usd,omitempty"`
	AlgoUsdRate        float64 `json:"algo_usd_rate,omitempty"`
	// Fee is the additive-fee breakdown (platform fee, refund, total debit)
	// the proxy derives from the operator-signed amount_charged and the ticket
	// box's open-time fee snapshot. Omitted when the proxy couldn't read the
	// snapshot. See hayaiFeeBreakdown.
	Fee *hayaiFeeBreakdown `json:"fee,omitempty"`
}

// hayaiFeeBreakdown is the additive-fee decomposition derived from the
// operator-signed amount_charged and the payer's effective fee rate (feeBps;
// the contract snapshots the same rate onto the ticket at open() as the
// settlement authority; see SPEC.md §3a "Open-time fee snapshot").
// amount_charged is the operator's base (net) take; platform_fee rides on top
// and is the payer's; total_debit is what the payer actually pays. The
// discount_bps field is retained for wire-shape stability but is always 0 — the
// HAY fee discount is retired. Present only when the rate was available; the
// whole `fee` object is omitted otherwise (escrow off, or the rate cache hasn't
// warmed). It is a nested object precisely so "rate absent" is distinguishable
// from a genuine 0 platform fee.
type hayaiFeeBreakdown struct {
	FeeBps               uint64  `json:"fee_bps"`
	DiscountBps          uint64  `json:"discount_bps"`
	PlatformFeeMicrousdc uint64  `json:"platform_fee_microusdc"`
	RefundMicrousdc      uint64  `json:"refund_microusdc"`
	TotalDebitMicrousdc  uint64  `json:"total_debit_microusdc"`
	TotalDebitUsd        float64 `json:"total_debit_usd,omitempty"`
}

// feeBreakdownFor builds the additive-fee breakdown for a settled request, or
// nil when the open-time snapshot wasn't read (haveFee == false). currency /
// decimals come from inferenceDenom; the USD figure is emitted only for USDC.
func feeBreakdownFor(amountCharged, maxPrice, feeBps, discountBps uint64, haveFee bool, currency string, decimals int) *hayaiFeeBreakdown {
	if !haveFee {
		return nil
	}
	b := escrow.ComputeFeeBreakdown(amountCharged, maxPrice, feeBps, discountBps)
	out := &hayaiFeeBreakdown{
		FeeBps:               feeBps,
		DiscountBps:          discountBps,
		PlatformFeeMicrousdc: b.NetFee,
		RefundMicrousdc:      b.Refund,
		TotalDebitMicrousdc:  b.TotalDebit,
	}
	if currency == "USDC" {
		out.TotalDebitUsd = float64(b.TotalDebit) / pow10(decimals)
	}
	return out
}

// feeRateCapable is the optional wallet capability for reading the live
// protocol-fee rate. *hayai.Wallet implements it; test fakes that don't simply
// make the breakdown unavailable (haveFee == false), preserving the prior
// behavior.
type feeRateCapable interface {
	ProtocolFeeBps(ctx context.Context) (feeBps uint64, err error)
}

// The production wallet must satisfy feeRateCapable. feeRateNow reaches it via a
// runtime type assertion (so test fakes can opt out), so without this static
// check a rename on either side would silently drop the payer-facing fee
// breakdown from every response instead of failing the build.
var _ feeRateCapable = (*hayai.Wallet)(nil)

const (
	// feeRateCacheTTL is how long a fetched fee rate is served before a
	// background refresh is kicked. The rate is the proxy payer's own and only
	// moves on a HAY-balance / oracle / fee change, so a coarse TTL is fine.
	feeRateCacheTTL = 60 * time.Second
	// feeRateRefreshTimeout bounds the background read so a wedged algod
	// can't leak a stuck refresh goroutine.
	feeRateRefreshTimeout = 5 * time.Second
)

// feeRateCache holds the proxy payer's live protocol-fee rate (feeBps) for the
// payer-facing breakdown, read straight from the contract's protocolFeeBps
// global. The HAY fee discount is retired, so there is no discount term to
// cache; the proxy pays from one address, so one value serves every request.
// Reads NEVER block on a chain call: a stale/cold cache returns what it has
// (haveFee == false until the first refresh lands) and kicks an async refresh,
// so the response path is never gated on the global read.
type feeRateCache struct {
	mu         sync.Mutex
	feeBps     uint64
	ok         bool
	fetchedAt  time.Time
	refreshing bool
}

// get returns the cached rate and triggers a single background refresh when the
// value is cold or older than feeRateCacheTTL.
func (c *feeRateCache) get(fetch func(context.Context) (uint64, error)) (feeBps uint64, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	stale := !c.ok || time.Since(c.fetchedAt) > feeRateCacheTTL
	if stale && !c.refreshing {
		c.refreshing = true
		go c.refresh(fetch)
	}
	return c.feeBps, c.ok
}

func (c *feeRateCache) refresh(fetch func(context.Context) (uint64, error)) {
	// Runs in a background goroutine for a cosmetic breakdown — a panic here
	// (or in fetch) must neither crash the proxy nor wedge refreshing. The
	// deferred reset always clears the flag so a future read can retry.
	defer func() {
		_ = recover()
		c.mu.Lock()
		c.refreshing = false
		c.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), feeRateRefreshTimeout)
	defer cancel()
	feeBps, err := fetch(ctx)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.feeBps, c.ok, c.fetchedAt = feeBps, true, time.Now()
	c.mu.Unlock()
}

// feeRateNow returns the proxy payer's cached effective fee rate for the
// payer-facing breakdown, kicking an async refresh when stale. ok == false (no
// breakdown) when the wallet can't read the rate or the cache hasn't warmed yet.
func (s *Server) feeRateNow() (feeBps uint64, ok bool) {
	w, capable := s.wallet.(feeRateCapable)
	if !capable {
		return 0, false
	}
	return s.feeRate.get(w.ProtocolFeeBps)
}

// WarmFeeRate kicks the first protocol-fee read at startup so the catalog is
// priced before any client asks for it.
//
// A cold read returns ok == false AND starts the refresh, so whoever triggers
// the warm is the one request that misses it — and under modelEntryFor a fee
// that isn't known publishes NO price at all. The client that pays for that is
// structurally the worst one: an OpenAI-compatible client fetches /v1/models
// once, at connect time, and caches what it gets for its own TTL. So the very
// first client to connect after a restart caches a price-less catalog and shows
// no cost for minutes, on a proxy whose pricing was correct the entire time.
// Hermes Agent does exactly this.
//
// It does NOT block, and the window is narrowed rather than closed: a client
// connecting inside the refresh RTT still reads a cold cache. What buys the
// narrowing is NOT boot work overlapping the read — there is essentially none
// left after this point (HTTPServer is a struct literal, the module serves no
// TLS, and what follows is a handful of log lines). It is that the read is
// issued when the proxy starts rather than when a tool first connects, and an
// operator starts the proxy seconds to minutes before pointing anything at it.
// It cannot be moved earlier to overlap the wallet's simulate: feeRateNow reads
// s.wallet, which does not exist until buildEscrowWalletFromClient returns.
//
// Blocking here instead would put a chain read on the startup path, which
// feeRateCache exists to avoid. A failed warm degrades to exactly the old
// behavior, since a later get() retries.
//
// Two consequences of reusing the request path's cache, both deliberate:
//
//   - The refresh goroutine runs on context.Background() with its own 5s cap,
//     so it is NOT bound to app.Run's context — an early Ctrl-C will not cancel
//     it and Shutdown does not join it. Bounded and detached by design; the
//     alternative is a cancellation seam on a cache every request also uses.
//   - A failed warm is SILENT (refresh drops the error and recovers panics).
//     The symptom an operator sees is a permanently price-less /v1/models
//     rather than a log line, so treat "no pricing in the catalog" as a chain
//     reachability symptom, not a pricing bug.
func (s *Server) WarmFeeRate() {
	_, _ = s.feeRateNow()
}

// verifyReservePrice runs the payer-side price checks (C1–C5, shared golden-
// vectored pricing.VerifyTicketPrice) against a just-reserved ticket before the
// proxy opens escrow against it. Returns the first violation, or nil to accept.
//
// It reads the advertised rates the node published for this model (per-model
// input/output/cache-read on op.ModelCapacities, operator-level min-charge on op)
// and the on-chain protocol fee. It fails open — accepts — when a reference is
// unavailable so an honest send is never blocked by cold catalog/fee state:
//   - the fee cache hasn't warmed yet (the max_price recompute needs feeBps);
//   - the operator published no capacity entry for this model (catalog miss) —
//     without advertised rates a zero ModelCapacity would read as "free" and
//     false-reject any priced ticket;
//   - the reserve carries an image-tool budget, an additive per-image microUSDC
//     amount folded into max_price that C1 would need to reproduce exactly —
//     deferred rather than risk false-rejecting an image-tool reserve.
//   - the model prices per-call tools (SPEC.md "Per-call tool pricing"): the
//     node folds a per-call tool-fee headroom into max_price. Unlike the image
//     budget this IS reproduced (not skipped) — pricing.ToolFeeReserveMicroUSDC
//     recomputes the identical headroom from the advertised rates and passes it
//     as the additive term to VerifyTicketPrice, so the exact max_price recompute
//     still reconciles AND the advertised-rate / min-charge / cache-read bounds
//     still run. Skipping instead would leave a hole where a signed token rate
//     above the advertised one goes unchecked, triggerable by advertising a
//     single free tool rate.
//
// Dedicated image / character / seconds tickets are skipped inside
// VerifyTicketPrice itself (priced by imageprice/videoprice, not per token).
func (s *Server) verifyReservePrice(op hayai.Operator, req ticket.ReserveRequest, t *ticket.Ticket) *pricing.Violation {
	if req.ImageToolBudget > 0 || req.ImageEditToolBudget > 0 {
		return nil
	}
	feeBps, ok := s.feeRateNow()
	if !ok {
		return nil
	}
	mc, mcOK := op.ModelCapacities[req.Model]
	if !mcOK {
		return nil // no advertised reference for this model — fail open
	}
	// Reproduce the per-call tool-fee headroom the node folds into max_price so the
	// max_price recompute reconciles and the advertised-rate / min-charge /
	// cache-read bounds keep running. 0 for a model that prices no tools (or only
	// free 0-rate ones), leaving verification byte-identical to before. The zs_
	// term uses the operator-advertised max_tool_iterations and the input term uses
	// the TICKET's input rate — the same inputs the node reserved with.
	maxIters := op.MaxToolIters
	if maxIters < 0 {
		maxIters = 0
	}
	toolReserve, terr := pricing.ToolFeeReserveMicroUSDC(
		uint64(maxIters),
		mc.MaxZsToolRateMicroUSDC(),
		mc.VendorToolCallCap,
		mc.MaxVendorToolRateMicroUSDC(),
		mc.VendorToolTokensPerCall,
		t.InputRate,
	)
	if terr != nil {
		return nil // headroom overflow (absurd operator config) — fail open, don't false-reject
	}
	adv := pricing.Advertised{
		InputUsdPer1M:         mc.InputUSDPer1M,
		OutputUsdPer1M:        mc.OutputUSDPer1M,
		CacheReadRateUsdPer1M: mc.CacheReadUSDPer1M,
		MinChargeOutputTokens: op.MinChargeOutputTokens,
		MinChargeMicroUSDC:    op.MinChargeMicroUSDC,
		// long_context (surcharge) tier. VerifyTicketPrice resolves the tier from
		// the ticket's OWN signed input_count (pricing.IsLongContext) and bounds the
		// signed rates against the tier-appropriate advertised rate. Feeding it
		// through also closes a real false-reject: without the tier, any future >2x
		// surcharge trips rate_bound (xAI's exact-2x passes the <= bound only by
		// coincidence). The per-operator values on mc are the authority — the
		// cross-operator aggregate is display-only and never reaches here.
		LongContextThresholdTokens:       mc.LongContextThresholdTokens,
		LongContextInputUsdPer1M:         mc.LongContextInputUSDPer1M,
		LongContextOutputUsdPer1M:        mc.LongContextOutputUSDPer1M,
		LongContextCacheReadRateUsdPer1M: mc.LongContextCacheReadUSDPer1M,
	}
	return pricing.VerifyTicketPrice(*t, adv, feeBps, req.InputCount, toolReserve, pricing.DefaultPolicy())
}

// retiredDiscountBps is the HAY fee discount — retired, so always 0. It is
// threaded into the payer-facing breakdown (the X-Zs-Discount-Bps header and
// the `discount_bps` field of the zs.usage frame) purely for wire-shape
// stability: those fields predate the discount's retirement and clients may
// still read them. There is no longer any source that produces a non-zero
// discount.
const retiredDiscountBps uint64 = 0

// hayaiUsageFrame builds the synthetic SSE frame emitted after the
// operator's signed receipt has been verified. openFees + settleFees
// are the *payer's* shares of the open and settle groups (operator's
// pool fees are excluded), summed into algo_fees_microalgos so the
// client sees a single "what did the payer pay in network fees"
// number. In the consensus-verified design both shares are 0 on the
// atomic path; only the standalone settle fallback contributes.
// When the payer's fee rate is readable (haveFee), the additive-fee
// breakdown (platform fee, refund, total debit) rides in the frame's
// `fee` object via feeBreakdownFor; it is omitted otherwise.
//
// Marshal cannot fail for this shape; JSON errors here would indicate
// a stdlib bug.
func hayaiUsageFrame(r *ticket.UsageReceipt, ticket *ticket.Ticket, op hayai.Operator, openFees, settleFees uint64, algoUSDPrice float64, feeBps, discountBps uint64, haveFee bool) transform.SSEFrame {
	currency, decimals := inferenceDenom(ticket)
	totalFees := openFees + settleFees
	u := hayaiUsage{
		Type:              hayaiUsageFrameEvent,
		TicketID:          r.TicketID,
		OperatorID:        op.ID,
		NodeID:            op.NodeID,
		OperatorOwnerAddr: op.OwnerAddr,
		ActualInputCount:  r.ActualInputCount,
		ActualOutputCount: r.ActualOutputCount,
		Inference: hayaiInferenceCost{
			Amount:   r.AmountCharged,
			Currency: currency,
			Decimals: decimals,
		},
		MaxPriceAmount:     ticket.MaxPrice,
		MinPriceAmount:     ticket.MinPrice,
		AlgoFeesMicroalgos: totalFees,
	}
	if r.AmountCharged > 0 {
		u.Inference.AmountUsd = inferenceUSD(r.AmountCharged, currency, decimals, algoUSDPrice)
	}
	if algoUSDPrice > 0 {
		u.AlgoFeesUsd = float64(totalFees) / 1_000_000 * algoUSDPrice
		u.AlgoUsdRate = algoUSDPrice
	}
	u.Fee = feeBreakdownFor(r.AmountCharged, ticket.MaxPrice, feeBps, discountBps, haveFee, currency, decimals)
	payload, _ := json.Marshal(u)
	return transform.SSEFrame{Event: hayaiUsageFrameEvent, Data: payload}
}

// verifyNonStreamReceipt decodes + verifies the X-Zs-Receipt
// header attached by the node. Absence of the header is logged at
// debug and tolerated; a present-but-invalid receipt is logged at
// warn and drives escrow.protest.
//
// Returns the parsed receipt plus the escrow submit (AckSettle or
// Protest) its verdict calls for, which the caller runs only after the
// client has its response. Receipt is nil when the header was absent or
// malformed — receipt-shape problems are recorded evidence, not a reason
// to withhold the already-decrypted response. submit is nil when there is
// nothing to put on chain.
func (s *Server) verifyNonStreamReceipt(ctx context.Context, headerVal, settleGroupHeaderVal, endpoint, model string, tkt *ticket.Ticket, op hayai.Operator, handle settlementHandle, plaintext []byte, algoUSDPrice float64, hop *hayai.RelayHop) (*ticket.UsageReceipt, settleSubmit) {
	if headerVal == "" {
		s.log.Debug("no receipt header on zs response; tolerating",
			opAttr(op),
			relayAttr(hop),
			slog.String("ticket_id", tkt.TicketID))
		return nil, nil
	}
	receipt, err := ticket.DecodeReceiptHeader(headerVal)
	if err != nil {
		s.log.Warn("receipt header malformed",
			opAttr(op),
			relayAttr(hop),
			slog.String("ticket_id", tkt.TicketID),
			slog.Any("err", err))
		return nil, nil
	}
	presignedSettleGroup := decodeSettleGroupHeader(s, settleGroupHeaderVal, op, tkt, hop)
	submit := s.checkReceipt(ctx, endpoint, model, tkt, op, handle, &receipt, wire.BodyHashOfBody(plaintext), plaintext, algoUSDPrice, presignedSettleGroup, hop)
	return &receipt, submit
}

// submitAfterResponse runs an escrow submit in the background, so the
// handler can return and the client receives its complete response
// without waiting on algod. WaitSettles lets shutdown drain these.
//
// The goroutine recovers its own panics: it is outside the HTTP
// middleware's recover, and a crash here would take down the payer's
// whole proxy, including the in-memory refund watchdog.
func (s *Server) submitAfterResponse(ticketID string, submit settleSubmit) {
	if submit == nil {
		return
	}
	s.settlesInFlight.Store(ticketID, struct{}{})
	s.settles.Go(func() {
		defer s.settlesInFlight.Delete(ticketID)
		defer func() {
			if r := recover(); r != nil {
				s.log.Error("escrow settle submit panicked",
					slog.String("ticket_id", ticketID),
					slog.Any("panic", r))
			}
		}()
		submit()
	})
}

// WaitSettles blocks until every background escrow submit has returned, or
// ctx is done. Call it after the HTTP server has stopped accepting
// requests. On timeout the error names the tickets still being submitted,
// since a submit that dies with the process is not recovered in-process:
// the refund watchdog is in-memory too.
func (s *Server) WaitSettles(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.settles.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		var ids []string
		s.settlesInFlight.Range(func(k, _ any) bool {
			ids = append(ids, k.(string))
			return true
		})
		slices.Sort(ids)
		return fmt.Errorf("%w; tickets still settling: %s", ctx.Err(), strings.Join(ids, ", "))
	}
}

// openSealedResponseMeta unseals one piece of post-response metadata — the
// X-Zs-Receipt / X-Zs-Settle-Group header value, or the `zs-settle-group` SSE
// frame — under K_response. Both are sealed because both are payer-linkable
// (the settle group names the payer address; the receipt carries ticket_id,
// which resolves to TicketRecord.payer on chain), and a relay forwards this
// response verbatim. Returns "" for an absent value, and logs + returns "" on
// a failed open so the caller degrades exactly as it does for an absent one.
//
// It goes through ResponseOpener.OpenHeader, which by construction does NOT
// advance the frame counter — the streaming caller passes the same opener it
// reads content frames with, so the `zs-settle-group` frame consuming no frame
// index is a property of the method rather than a rule the read loop has to
// remember.
func openSealedResponseMeta(s *Server, sealedVal string, opener *wire.ResponseOpener, tkt *ticket.Ticket, name string, op hayai.Operator, hop *hayai.RelayHop) string {
	if sealedVal == "" {
		return ""
	}
	plaintext, err := opener.OpenHeader(sealedVal, name)
	if err != nil {
		s.log.Warn("sealed response metadata failed to open",
			opAttr(op),
			relayAttr(hop),
			slog.String("metadata", name),
			slog.String("ticket_id", tkt.TicketID),
			slog.Any("err", err))
		return ""
	}
	return string(plaintext)
}

// decodeSettleGroupHeader parses the optional X-Zs-Settle-Group
// header. Absence is normal (older nodes; soft-failure on the node
// side); presence-but-malformed is logged at warn so an operator
// emitting bad bytes is observable, but the proxy still falls back
// to the standalone-ack path.
func decodeSettleGroupHeader(s *Server, headerVal string, op hayai.Operator, tkt *ticket.Ticket, hop *hayai.RelayHop) []types.SignedTxn {
	if headerVal == "" {
		return nil
	}
	group, err := escrow.DecodeSettleGroup(headerVal)
	if err != nil {
		s.log.Warn("settle-group header malformed; falling back to standalone ack",
			opAttr(op),
			relayAttr(hop),
			slog.String("ticket_id", tkt.TicketID),
			slog.Any("err", err))
		return nil
	}
	return group
}

// runReceiptChecks dispatches to the shared verifier and drives the
// on-chain follow-up via the open handle:
//
//   - Happy path → OpenHandle.AckSettle(receipt). If an operator-side
//     settle claim has already posted and matches, this finalizes and
//     disburses. If the operator hasn't posted yet, this records the
//     payer's pending claim and the operator's subsequent call
//     finalizes.
//   - ReceiptViolationBodyHash → OpenHandle.Protest(receipt, excerpt).
//     The excerpt in v1 is the reconstructed plaintext (truncated to
//     the contract's maxDisputeExcerptBytes) — enough for the off-chain
//     arbiter to inspect.
//   - ReceiptViolationSig / ReceiptViolationAmount → log only; the
//     contract refuses these on-chain, so re-submitting would just
//     waste fees. Dispute evidence is still retained via logs.
//
// The handle is received via the settlementHandle interface (satisfied
// by *hayai.OpenHandle in production and by test fakes); this keeps
// runReceiptChecks testable without spinning up real algod or
// escrow clients.
func (s *Server) runReceiptChecks(
	ctx context.Context,
	endpoint, model string,
	ticket *ticket.Ticket,
	op hayai.Operator,
	handle settlementHandle,
	receipt *ticket.UsageReceipt,
	computed [32]byte,
	plaintext []byte,
	algoUSDPrice float64,
	presignedSettleGroup []types.SignedTxn,
	hop *hayai.RelayHop,
) uint64 {
	submit := s.checkReceipt(ctx, endpoint, model, ticket, op, handle, receipt, computed, plaintext, algoUSDPrice, presignedSettleGroup, hop)
	if submit == nil {
		return 0
	}
	return submit()
}

// settleSubmit is the on-chain half of receipt handling (AckSettle or
// Protest). It returns the payer-paid settle fee, 0 when none was paid.
type settleSubmit func() uint64

// checkReceipt is runReceiptChecks without the submit: it verifies the
// receipt, records the spend outcome, and returns the escrow submit the
// verdict calls for, or nil when there is nothing to submit. The split
// exists for the non-streaming responder, which must not hold the
// client's response for an algod round-trip (up to settleSubmitTimeout),
// so it writes the response first and runs the submit after.
func (s *Server) checkReceipt(
	ctx context.Context,
	endpoint, model string,
	ticket *ticket.Ticket,
	op hayai.Operator,
	handle settlementHandle,
	receipt *ticket.UsageReceipt,
	computed [32]byte,
	plaintext []byte,
	algoUSDPrice float64,
	presignedSettleGroup []types.SignedTxn,
	hop *hayai.RelayHop,
) settleSubmit {
	// Escrow finalization (AckSettle / Protest) must outlive the client
	// request. The receipt frame is processed on the upstream (node→proxy)
	// connection, which stays alive even after the client has disconnected —
	// a JetBrains-style client that cancels or closes the moment it has its
	// content cancels r.Context(), and submitting the settle on that context
	// fails with "algod: SendRawTransaction: context canceled", leaving the
	// on-chain open dangling until the node's settlement watchdog
	// force-finalizes it via settleLapsed (extra on-chain work + delayed
	// payout). Detach from the request lifecycle so the cheap in-band atomic
	// settle still lands; keep a bound (settleSubmitTimeout) so a wedged
	// algod can't leak a goroutine. The bound starts when the submit runs,
	// not when the receipt was checked, so a deferred submit gets its full
	// budget.
	detached := context.WithoutCancel(ctx)
	withSettleCtx := func(fn func(settleCtx context.Context) uint64) settleSubmit {
		return func() uint64 {
			settleCtx, cancelSettle := context.WithTimeout(detached, settleSubmitTimeout)
			defer cancelSettle()
			return fn(settleCtx)
		}
	}

	err := hayai.VerifyReceipt(hayai.ReceiptCheck{
		Ticket:       ticket,
		Operator:     op,
		Receipt:      receipt,
		ComputedHash: computed,
	})
	if err == nil {
		// Info-level: one line per paying request with the
		// node-authoritative usage + microUSDC charge. This is the
		// primary observability hook the operator reads to watch
		// spend in real time.
		currency, decimals := inferenceDenom(ticket)
		paidAttrs := []slog.Attr{
			slog.String("endpoint", endpoint),
			slog.String("model", model),
			opAttr(op),
			relayAttr(hop),
			slog.String("ticket_id", ticket.TicketID),
			slog.Uint64("actual_input_count", receipt.ActualInputCount),
			slog.Uint64("cached_input_count", receipt.CachedInputCount),
			slog.Uint64("actual_output_count", receipt.ActualOutputCount),
			slog.Uint64("amount_microusdc", receipt.AmountCharged),
		}
		if usd := inferenceUSD(receipt.AmountCharged, currency, decimals, algoUSDPrice); usd > 0 {
			paidAttrs = append(paidAttrs, slog.String("amount_usd", fmt.Sprintf("$%.6f", usd)))
		}
		s.log.LogAttrs(ctx, slog.LevelInfo, "zs request paid", paidAttrs...)
		// Record the actual settled charge (<= MaxPrice) against the daily
		// spend guard and drop the ticket's reserved ceiling — this is what
		// `zs status` reports as spent today. Independent of the on-chain
		// AckSettle below (and runs even when handle is nil in no-escrow mode).
		if s.spend != nil {
			s.spend.Settle(ticket.TicketID, receipt.AmountCharged)
		}
		if handle == nil {
			return nil
		}
		return withSettleCtx(func(settleCtx context.Context) uint64 {
			// A failing ack is operational noise, not a client-visible error:
			// the refund watchdog keeps tracking the ticket, so the escrow is
			// still recovered on chain.
			var settleFees uint64
			atomic := len(presignedSettleGroup) > 0
			txid, fee, groupRejected, err := handle.AckSettle(settleCtx, receipt, presignedSettleGroup)
			if groupRejected && s.nodeExcluder != nil {
				// The node handed a fraudulent atomic settle group (rekey /
				// ClearState / value mismatch vs its own receipt). Proven
				// misbehaviour — hard-exclude this (operatorId,nodeId) from all
				// further selection this process's lifetime (target AND relay).
				// The payment is unaffected: AckSettle already fell back to the
				// standalone receipt-sourced ack (pendingBy=PAYER, refundInactive-
				// eligible).
				ref := hayai.RefOf(op)
				s.nodeExcluder.ExcludeNode(ref)
				s.log.Warn("node excluded: handed a fraudulent settle group",
					slog.String("ticket_id", ticket.TicketID),
					slog.Uint64("operator_id", op.ID),
					slog.Uint64("node_id", op.NodeID))
			}
			// The 2-tx atomic group actually FINALIZED (deleted the ticket box)
			// only when it wasn't rejected. When groupRejected is true, AckSettle
			// refused the group and fell back to the standalone payer-ack — which
			// posts a pendingBy=PAYER claim the refund watchdog must KEEP tracking
			// (refundInactive at the deadline), exactly like the no-settle-group
			// case. So the ticket header being present is not enough; gate the
			// watchdog Resolve on the group having truly finalized.
			settledAtomically := atomic && !groupRejected
			switch {
			case err != nil:
				s.log.Warn("ack-settle failed",
					slog.String("ticket_id", ticket.TicketID),
					slog.Bool("atomic", atomic),
					slog.Bool("group_rejected", groupRejected),
					slog.Any("err", err))
			default:
				settleFees = fee
				// Info when the payer paid a fee: the non-streaming usage
				// headers were written before this submit and cannot report it.
				level := slog.LevelDebug
				if fee > 0 {
					level = slog.LevelInfo
				}
				s.log.Log(settleCtx, level, "ack-settle submitted",
					slog.String("ticket_id", ticket.TicketID),
					slog.String("txid", txid),
					slog.Bool("atomic", settledAtomically),
					slog.Uint64("fee_microalgos", fee))
				if settledAtomically {
					// The 2-tx group finalized and deleted the ticket box —
					// nothing left for the refund watchdog to recover. A
					// standalone ack (no group, OR a rejected-then-fallback group)
					// stays tracked on purpose: it records a pending payer claim
					// the operator must still match, and refundInactive is exactly
					// the deadline path when the operator never acks it.
					s.refunds.Resolve(ticket.TicketID)
				}
			}
			return settleFees
		})
	}
	re, ok := hayai.AsReceiptError(err)
	if !ok {
		// VerifyReceipt always returns *ReceiptError or nil today, but
		// keep a guard so a future caller passing some other non-nil
		// error doesn't panic on the nil-deref of re.Violation below.
		re = &hayai.ReceiptError{Violation: hayai.ReceiptOK, Err: err}
	}
	s.log.Warn("receipt verification failed",
		slog.String("endpoint", endpoint),
		slog.String("model", model),
		opAttr(op),
		relayAttr(hop),
		slog.String("ticket_id", ticket.TicketID),
		slog.String("violation", re.Violation.String()),
		slog.Any("err", err))
	// The receipt didn't verify, so the reservation didn't legitimately cost
	// anything (settlement is disputed via Protest below, or the escrow
	// refunds/lapses on-chain). Drop the ticket's reserved ceiling without
	// recording any spend.
	if s.spend != nil {
		s.spend.Release(ticket.TicketID)
	}
	if handle == nil || re.Violation != hayai.ReceiptViolationBodyHash {
		return nil
	}
	excerpt := truncateDisputeExcerpt(plaintext, disputeExcerptCap)
	return withSettleCtx(func(settleCtx context.Context) uint64 {
		if txid, perr := handle.Protest(settleCtx, receipt, excerpt, protestReasonForViolation(re.Violation)); perr != nil {
			s.log.Warn("protest failed",
				slog.String("ticket_id", ticket.TicketID),
				slog.String("reason", re.Violation.String()),
				slog.Any("verification_err", err),
				slog.Any("submit_err", perr))
		} else {
			s.log.Warn("protest submitted",
				slog.String("ticket_id", ticket.TicketID),
				slog.String("txid", txid),
				slog.String("reason", re.Violation.String()),
				slog.Any("verification_err", err))
			// Frozen ticket: refundInactive reverts on FROZEN, so the refund
			// watchdog has nothing to do — resolution is off-chain arbitration.
			s.refunds.Resolve(ticket.TicketID)
		}
		return 0
	})
}

// protestReasonForViolation maps a verification violation to the
// payer-asserted reason code carried on the on-chain protest call.
// Today only ReceiptViolationBodyHash routes to a Protest submission
// (sig/amount violations are log-only because the contract would
// reject them); the full mapping exists so future protest triggers
// slot in without a wire-format break.
func protestReasonForViolation(v hayai.ReceiptViolation) escrow.ProtestReasonCode {
	switch v {
	case hayai.ReceiptViolationBodyHash:
		return escrow.ProtestReasonBodyHash
	case hayai.ReceiptViolationSig:
		return escrow.ProtestReasonReceiptSig
	case hayai.ReceiptViolationAmount:
		return escrow.ProtestReasonAmount
	default:
		return escrow.ProtestReasonUnspecified
	}
}

// disputeExcerptCap mirrors the contract's maxDisputeExcerptBytes
// default (1800 bytes). The contract enforces the ceiling on-chain; the
// proxy pre-truncates so the submission never reverts on size alone.
// If the operator bumps the ceiling via setMaxDisputeExcerptBytes,
// the proxy side can follow by bumping this constant — submitting
// below the contract's current cap is always safe.
const disputeExcerptCap = 1800

// settleSubmitTimeout bounds the detached escrow-finalization submit
// (AckSettle / Protest) that checkReceipt builds, whether it runs inline
// (streaming) or in the background (non-streaming). These calls are deliberately
// run on a context decoupled from the client request (so a client that
// disconnects the instant it has its content can't abort the on-chain
// settle), but a context with no cancellation and no deadline would leak
// the goroutine if algod wedged. The submit is a single
// SendRawTransactionGroup round-trip (no wait-for-confirmation — see
// escrow.SubmitPresignedSettleGroup), so a short bound is ample.
const settleSubmitTimeout = 15 * time.Second

// truncateDisputeExcerpt returns at most n bytes of body, taking the
// head. Head-truncation is fine for the dispute arbiter's purposes —
// the receipt's body_hash already commits to the full plaintext, so
// the excerpt is a partial demonstration not a hash pre-image.
// truncateForLog bounds an untrusted upstream string before it reaches a log
// line or a client-visible message. Operator-controlled headers are unbounded in
// practice (net/http allows ~10MB of response headers by default), so echoing one
// verbatim lets a hostile operator write megabytes into the payer's log file.
//
// ToValidUTF8 because the cut can land mid-rune and the result is JSON-encoded.
func truncateForLog(s string, n int) string {
	if len(s) > n {
		s = s[:n] + "…"
	}
	return strings.ToValidUTF8(s, "\uFFFD")
}

func truncateDisputeExcerpt(body []byte, n int) []byte {
	if len(body) <= n {
		out := make([]byte, len(body))
		copy(out, body)
		return out
	}
	out := make([]byte, n)
	copy(out, body[:n])
	return out
}

// flattenFrames concatenates stream plaintext frames in index order
// to produce the same byte sequence the node hashed for
// receipt.BodyHash. Only used for the dispute-excerpt path; the
// hash comparison itself goes through wire.BodyHashFromFrames.
func flattenFrames(frames [][]byte) []byte {
	total := 0
	for _, f := range frames {
		total += len(f)
	}
	out := make([]byte, 0, total)
	for _, f := range frames {
		out = append(out, f...)
	}
	return out
}

// buildHayaiFrameFactory handles the streaming path. It does the same
// commit_k verification as the non-stream responder (once, when the
// wrapped key arrives), decrypts content frames in order, accumulates
// their plaintext for body_hash, and on the terminal zs-receipt
// event runs the same three verification checks as the non-stream
// responder. The signed receipt itself is not forwarded — but a
// small, unsigned `zs.usage` SSE frame is emitted in its place so
// streaming clients can render per-request usage + microUSDC cost.
func (s *Server) buildHayaiFrameFactory(
	ctx context.Context,
	ephemeral *age.X25519Identity,
	txID string,
	tkt *ticket.Ticket,
	op hayai.Operator,
	handle settlementHandle,
	timer *cryptoTimer,
	endpoint, model string,
	algoUSDPrice float64,
	openFees uint64,
	hop *hayai.RelayHop,
	genComplete *atomic.Bool,
	emitUsageFrame bool,
	format clientFormat,
) frameTransformFactory {
	return func(upstreamResp *http.Response) (frameTransform, error) {
		wrappedKey := upstreamResp.Header.Get(wire.ResponseKeyHeader)
		if wrappedKey == "" {
			// An operator that opens an SSE stream without a sealed
			// response key would be streaming plaintext through an
			// admitted ticket. Refuse — there is no plaintext path.
			s.log.Warn("operator opened SSE stream without sealed key — protocol violation",
				opAttr(op),
				relayAttr(hop))
			return nil, fmt.Errorf("operator did not seal the SSE stream")
		}

		t0 := time.Now()
		responseKey, err := wire.UnwrapResponseKey(wrappedKey, ephemeral)
		timer.recordDecrypt(time.Since(t0))
		if err != nil {
			return nil, fmt.Errorf("unwrap response key: %w", err)
		}

		// Same commit_k check as the non-stream responder: the operator must
		// seal with the K it committed at reserve (ticket.commit_k =
		// sha256(K_response)), or §3b case (a) key-substitution fraud would be
		// undetectable on streams — the frames below decrypt fine under
		// whatever key the header delivered. Failing here aborts before any
		// frame is pumped (502 stream_setup).
		if err := verifyCommitK(tkt, responseKey); err != nil {
			return nil, err
		}

		// One opener owns the SPEC § 5.3 frame counter for this stream:
		// OpenNextFrame advances it, OpenHeader does not. The read loop below
		// therefore never touches an index, which is what it used to do at
		// three separate branches — including one that advanced after a FAILED
		// receipt open, disagreeing with the reference client.
		opener, err := wire.NewResponseOpener(responseKey, txID, tkt.TicketID)
		if err != nil {
			return nil, fmt.Errorf("build response opener: %w", err)
		}

		// Pre-signed atomic settle group is delivered as an SSE frame
		// (`zs-settle-group`) for streams — the analogue of the
		// X-Zs-Settle-Group header on non-streaming. The node
		// emits it BEFORE the `zs-receipt` frame so this slot is
		// populated by the time runReceiptChecks runs.
		var presignedSettleGroup []types.SignedTxn

		var (
			contentFrames      [][]byte
			recordedResponseID bool
			recordResponseID   = s.responseAffinity != nil && endpoint == endpointResponses
			// receiptSeen makes settlement fire at most once per stream. A node
			// controls how many zs-receipt frames it emits, and runReceiptChecks
			// drives real, irreversible actions: AckSettle / Protest on chain, and
			// the payer's spend accounting. Two frames let a misbehaving operator
			// pick both branches — a bad-signature receipt to make the payer's
			// guard Release the reservation, then a valid one whose Settle finds
			// nothing open and so records NO spend, while AckSettle still pays out.
			// That makes every charge invisible to spend.daily_cap_usdc, which is
			// the payer's only defense against exactly that operator.
			receiptSeen bool
		)
		return func(f transform.SSEFrame) (transform.SSEFrame, error) {
			switch f.Event {
			case wire.StreamEventMarker:
				// Sealed hayai frame. Shape of the plaintext is opaque
				// to the proxy — it could be an OpenAI content delta, a
				// function-call fragment, or a hayai-specific event the
				// node emits (e.g. response.zs_tool_call.in_progress
				// status frames during server-side tool rounds). The
				// proxy decrypts, includes the plaintext in the body-
				// hash accumulator for receipt verification, and
				// forwards the bytes to the client unchanged.
				tf := time.Now()
				frameIndex := opener.FrameIndex()
				plaintext, err := opener.OpenNextFrame(f.Data)
				timer.recordDecrypt(time.Since(tf))
				if err != nil {
					return transform.SSEFrame{}, fmt.Errorf("decrypt sse frame: %w", err)
				}
				// -debug-bodies escape hatch: dump each decrypted frame as we
				// forward it, so a cancelled stream still shows what (if
				// anything) the node sent. No-op unless the flag is on.
				s.debugDumpResponseFrame(endpoint, op.ID, tkt.TicketID, frameIndex, plaintext)
				// Terminal-frame classification is the shared, golden-vectored
				// wire.ClassifyStreamFrame (SPEC § 5.3 "Consuming the settlement
				// tail") — the reference client answers it with the same code,
				// because a side that gets it wrong drops the settlement tail.
				verdict := wire.ClassifyStreamFrame(plaintext, streamAPIFor(endpoint))
				// Surface an operator/upstream error frame (default-on WARN).
				// Control-plane error, not completion content — see
				// wire.StreamErrorMessage. This is the line that turns a silent
				// "0 tokens, client disconnected" into a stated cause.
				if verdict.Error {
					s.log.Warn("operator returned stream error",
						opAttr(op), relayAttr(hop),
						slog.String("ticket_id", tkt.TicketID),
						slog.String("error", verdict.Message))
				}
				// genComplete is the signal forwardRawStream needs BEFORE the
				// receipt frame: a client that closes the instant it has what it
				// came for (JetBrains closes on finish_reason:"stop"; SDKs close
				// on an error event within milliseconds) disconnects between
				// this frame and the receipt, and the proxy uses this flag to
				// drain the tail instead of cancelling.
				//
				// Both terminal kinds need the drain, for opposite parties. On a
				// completed generation it pays the operator for content already
				// delivered. On an error frame it protects the PAYER: the node
				// writes the error, then the zero-cost receipt + settle group,
				// then [DONE]. Cancelling there meant no AckSettle ran and the
				// ticket sat PENDING(operator) until settleLapsed finalized the
				// operator's claim — a claim the payer never received the
				// receipt to verify or protest, since settleLapsed reads payer
				// silence as acceptance.
				if genComplete != nil && verdict.Terminal && !genComplete.Load() {
					genComplete.Store(true)
				}
				// Record response_id once per stream. ExtractResponseIDFromFrame
				// matches both response.created (first frame per the Responses
				// API spec) and response.completed (last frame, kept as a
				// fallback if a server quirk delays response.created). Until
				// one of those frames lands we re-attempt parsing on every
				// frame — sub-µs per call and bounded by stream length, so
				// the cost is negligible. Once recorded, recordedResponseID
				// short-circuits the rest of the stream.
				if recordResponseID && !recordedResponseID {
					if id := hayai.ExtractResponseIDFromFrame(plaintext); id != "" {
						s.responseAffinity.Record(op.ID, op.NodeID, []string{id})
						recordedResponseID = true
					}
				}
				// Copy before keeping — the SSE pump reuses buffers. The
				// accumulator MUST hold the node's original chat bytes: the
				// receipt's body_hash is computed over them (BodyHashFromFrames),
				// so the legacy-completions reshape below applies only to the
				// bytes forwarded to the client, never to contentFrames.
				stored := make([]byte, len(plaintext))
				copy(stored, plaintext)
				contentFrames = append(contentFrames, stored)
				out := plaintext
				if format == formatLegacyCompletions {
					out = completionsChunkFromChat(plaintext)
				}
				return transform.SSEFrame{Data: out}, nil

			case wire.StreamEventSettleGroup:
				// Sealed SSE frame carrying the operator's pre-signed atomic
				// settle group. Cache the decoded value so the upcoming
				// `zs-receipt` frame's runReceiptChecks → AckSettle can use it
				// for an atomic submit (payer pays 0 ALGO). Sealed under the
				// header AAD, not the frame AAD, so it does not consume a
				// frame index — the receipt frame after it must land on the
				// index the content frames left off at. OpenHeader is the
				// method that cannot advance, so that is now structural rather
				// than a rule this branch has to remember.
				sg := openSealedResponseMeta(s, string(f.Data), opener, tkt, wire.SealedHeaderSettleGroup, op, hop)
				presignedSettleGroup = decodeSettleGroupHeader(s, sg, op, tkt, hop)
				return transform.SSEFrame{}, nil // swallowed; client doesn't see it

			case wire.StreamEventReceipt:
				tf := time.Now()
				plaintext, err := opener.OpenNextFrame(f.Data)
				timer.recordDecrypt(time.Since(tf))
				if err != nil {
					s.log.Warn("decrypt receipt frame failed",
						opAttr(op),
						relayAttr(hop),
						slog.String("ticket_id", tkt.TicketID),
						slog.Any("err", err))
					// The index does NOT advance on a failed open — see
					// OpenNextFrame. This branch used to advance it, which the
					// reference client never did; no observer distinguished the
					// two only because the receipt is the last sealed frame.
					return transform.SSEFrame{}, nil // swallow; client doesn't see the receipt
				}
				var receipt ticket.UsageReceipt
				if err := json.Unmarshal(plaintext, &receipt); err != nil {
					s.log.Warn("parse receipt frame failed",
						opAttr(op),
						relayAttr(hop),
						slog.String("ticket_id", tkt.TicketID),
						slog.Any("err", err))
					return transform.SSEFrame{}, nil
				}
				if receiptSeen {
					// Second (or later) receipt for this stream: settlement already
					// ran and is not re-runnable. Swallow it and say so — a compliant
					// node emits exactly one.
					s.log.Warn("operator emitted more than one zs-receipt frame; ignoring the extra",
						opAttr(op),
						relayAttr(hop),
						slog.String("ticket_id", tkt.TicketID))
					return transform.SSEFrame{}, nil
				}
				receiptSeen = true
				// Reconstructed plaintext for the dispute-excerpt path.
				// We pass the flat concat of content frames — matches the
				// body_hash the receipt claimed, so truncating it head-
				// wise preserves an arbiter-meaningful excerpt.
				flat := flattenFrames(contentFrames)
				settleFees := s.runReceiptChecks(
					ctx,
					endpoint,
					model,
					tkt,
					op,
					handle,
					&receipt,
					wire.BodyHashFromFrames(contentFrames),
					flat,
					algoUSDPrice,
					presignedSettleGroup,
					hop,
				)
				if !emitUsageFrame {
					// OpenAI-compatible default: settlement ran above; we just
					// don't inject the non-OpenAI `zs.usage` frame that
					// strict clients (JetBrains/Koog) can't parse. Swallow it
					// like the settle-group frame — the client sees only the
					// standard content stream + [DONE].
					return transform.SSEFrame{}, nil
				}
				// Payer-facing fee breakdown from the proxy payer's cached
				// protocolFeeBps (background-refreshed; non-blocking).
				feeBps, haveFee := s.feeRateNow()
				return hayaiUsageFrame(&receipt, tkt, op, openFees, settleFees, algoUSDPrice, feeBps, retiredDiscountBps, haveFee), nil

			default:
				return f, nil // non-hayai event (e.g. [DONE]) passes through
			}
		}, nil
	}
}

// streamAPIFor maps a proxy route to the event vocabulary its frames use, for
// wire.ClassifyStreamFrame. /v1/completions is emulated on top of chat
// (completions.go), so it classifies as chat — the node never learns it began
// as a completions call, and the reshape happens after this point.
func streamAPIFor(endpoint string) wire.StreamAPI {
	if endpoint == endpointResponses {
		return wire.StreamAPIResponses
	}
	return wire.StreamAPIChat
}

// responseErrorMessage is the proxy's thin alias for the shared, golden-vectored
// wire.StreamErrorMessage, which recognizes both error shapes (chat
// {"error":{...}} and the /v1/responses {"type":"error"} event). It stays a
// named function here only because the two non-stream call sites read better
// with it and because the reason it is called at all is proxy-specific
// (the streaming path reads the same answer off wire.ClassifyStreamFrame):
//
// The proxy logs this (WARN, default-on) so a request that fails
// post-admission — e.g. the upstream rejecting the body — is diagnosable on
// the payer's own process without enabling -debug-bodies. This is a
// DELIBERATE, narrow exception to the proxy's no-content rule: an error
// envelope is control-plane, NOT prompt or completion content, and the proxy
// is a single-user process the payer runs for themselves. Prompt and
// completion content stay unlogged. See proxy/AGENTS.md.
//
// Do NOT reimplement the shape matching here. It is also the terminal-frame
// predicate behind the receipt-tail drain (SPEC § 5.3 "Consuming the
// settlement tail"), so a shape this misses doesn't just go unlogged — its
// ticket loses the in-band settle and the payer's chance to check the receipt
// against the operator's claim. That is exactly how the Responses shape stayed
// invisible on both counts until it was moved into proto.
func responseErrorMessage(plaintext []byte) (string, bool) {
	return wire.StreamErrorMessage(plaintext)
}

// verifyCommitK checks that the operator sealed the response with the K
// it committed to at reserve time. Mismatch is cryptographic proof of
// misbehavior — fail closed and let the caller surface a proxy_error.
func verifyCommitK(tkt *ticket.Ticket, key [wire.ResponseKeySize]byte) error {
	got := ticket.CommitResponseKey(key)
	gotB64 := base64.StdEncoding.EncodeToString(got[:])
	if gotB64 != tkt.CommitK {
		return errors.New("commit_k mismatch: operator sealed with a different key than it promised at reserve time")
	}
	return nil
}

// estimateTokens produces a safe upper bound on input_tokens plus a
// concrete max_output_tokens for the reserve call. The estimator is
// model-agnostic — it overcounts on purpose, and the escrow + operator's
// signed usage receipt reconcile the bound to actual usage.
//
// The only remaining hard failure is "no max_output anywhere": the
// node still needs a concrete ceiling to compute max_price, and silently
// guessing one would mask configuration drift.

// defaultToolHeadroomPerIteration / reserveMinInputCount mirror the node's
// zs.reserve defaults, used when the operator advertises neither on
// /v1/zs/details (a pre-field node). The node re-clamps whatever the proxy
// sends, so these only affect the reserve magnitude, never correctness.
const (
	defaultToolHeadroomPerIteration uint64 = 4000
	reserveMinInputCount            uint64 = 256
)

// reserveInputCount sizes the input_count to escrow for a reserve against op:
// the tight body bound plus a tool-loop headroom term when the request
// carries tools, floored and capped at contextWindow − maxOutputTokens (SPEC
// §3a). A previous_response_id chain hides its accumulated history from the
// node, so it reserves worst-case (the whole window) when a window is
// declared. The node re-clamps and reconciles actual usage against this
// value, so shrinking it below the window is safe — over-reservation only
// widened the payer's escrow lock.
// boundVersionFor picks the tokenize bound version to size a reserve against
// this operator with. v2 only when the target advertises >= 9.2 — sizing v2
// against an older node fails closed with input_budget_exceeded, because the
// node would measure the same body with the wider v1 bound and see the smaller
// reserve as an under-declaration.
func boundVersionFor(op hayai.Operator) uint8 {
	if wire.UsesTightInputBound(op.ProtoVersion) {
		return tokenize.BoundVersion2
	}
	return tokenize.BoundVersion1
}

// reserveInputCount sizes the input_count to escrow for a reserve against op:
// the tight body bound plus a tool-loop headroom term when the request
// carries tools, floored and capped at contextWindow − maxOutputTokens (SPEC
// §3a). It returns the bound version used, which the caller MUST put on the
// reserve request so the node re-measures with the same function.
//
// The body bound is computed here rather than taken from the pre-flight
// tokenize.Estimate because the version is PER-OPERATOR: a 9.2 node and a 9.1
// node get different (correct) numbers for the same body in the same dispatch.
func reserveInputCount(op hayai.Operator, model string, body []byte, maxOutputTokens uint64) (count uint64, boundVersion uint8) {
	boundVersion = boundVersionFor(op)
	bodyBound := tokenize.InputTokenBoundVersion(body, boundVersion)

	var contextWindow uint64
	if mc, ok := op.ModelCapacities[model]; ok {
		contextWindow = mc.ContextWindow
	}
	// Server-side response chain: reserve the model's full worst case, since
	// the node can't see (and this bound can't measure) the hidden history.
	// Only possible with a declared window; without one it falls through to
	// the body-bound path and the operator accepts the subsidy risk.
	if tokenize.BodyHasPreviousResponseID(body) && contextWindow > maxOutputTokens {
		return contextWindow - maxOutputTokens, boundVersion
	}
	perIter := op.ToolHeadroomPerIteration
	if perIter == 0 {
		perIter = defaultToolHeadroomPerIteration
	}
	var iters uint64
	if op.MaxToolIters > 0 {
		iters = uint64(op.MaxToolIters)
	}
	// Headroom rides only on tools that grow the SERVING side's context — the
	// node's own zs_ loop, or a vendor-hosted tool the upstream re-prefills. A
	// body carrying only caller-executed function tools (the coding-agent /
	// client-side-MCP case) drives no growth here: the agent runs each tool and
	// re-issues, and that request is measured and paid for on its own.
	return tokenize.ReserveInputCount(
		bodyBound, inject.BodyDrivesServerSideToolGrowth(body), iters, perIter,
		maxOutputTokens, contextWindow, reserveMinInputCount), boundVersion
}

func (s *Server) estimateTokens(model, endpoint string, body []byte) (tokenize.Estimate, error) {
	if s.tokenizer == nil {
		return tokenize.Estimate{}, errors.New("tokenizer not configured")
	}
	return tokenize.EstimateWithRegistry(s.tokenizer, tokenize.Request{
		Model:    model,
		Body:     body,
		Endpoint: tokenize.Endpoint(endpoint),
	})
}

// writeTokenizeError maps tokenize errors to the OpenAI-shaped response
// surfaces the reserve endpoint itself would produce, so the client sees
// the same error code whether the proxy refused up front or the node did.
func (s *Server) writeTokenizeError(w http.ResponseWriter, endpoint, model string, err error) {
	switch {
	case errors.Is(err, tokenize.ErrMaxOutputRequired):
		writeError(w, newError("max_output_required",
			"request omits max_tokens/max_completion_tokens/max_output_tokens and no default is configured for this model"))
	default:
		s.log.Warn("tokenize failed",
			slog.String("endpoint", endpoint),
			slog.String("model", model),
			slog.Any("err", err))
		writeError(w, newError("tokenize", "input tokenization failed"))
	}
}

// medianOf returns the median of vs, or 0 for an empty slice. It sorts a copy —
// the caller's slice order is meaningful elsewhere.
func medianOf(vs []float64) float64 {
	if len(vs) == 0 {
		return 0
	}
	sorted := append([]float64(nil), vs...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}
