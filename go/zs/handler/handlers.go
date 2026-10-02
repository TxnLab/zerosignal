/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"slices"
	"strconv"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/inject"
	hayai "github.com/TxnLab/zerosignal/go/zs"
)

// MaxClientBodyBytes caps the size of an inbound request body the proxy
// will buffer. OpenAI-shaped JSON bodies are typically tens of KB; 16 MiB
// leaves generous headroom for large tool-call arguments while keeping a
// single malicious client from exhausting memory.
const MaxClientBodyBytes = 16 << 20

// Endpoint paths used both as ServeMux patterns and as the `endpoint`
// argument threaded through dispatchHayai for routing decisions
// (notably the response_id pin gate, which is /v1/responses-only).
const (
	endpointChatCompletions = "/v1/chat/completions"
	endpointResponses       = "/v1/responses"
	endpointImages          = "/v1/images/generations"
	endpointImageEdits      = "/v1/images/edits"
)

// parseImageRequestN reads only the `n` field from an OpenAI
// /v1/images/generations request body. Defaults to 1 when omitted,
// rejects < 1. The model field is read separately via hayai.ExtractModel.
func parseImageRequestN(body []byte) (n int, size, quality string, err error) {
	var raw struct {
		N       *int   `json:"n,omitempty"`
		Size    string `json:"size,omitempty"`
		Quality string `json:"quality,omitempty"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return 0, "", "", errors.New("parse image request: invalid JSON")
	}
	n = 1
	if raw.N != nil {
		n = *raw.N
	}
	if n < 1 {
		return 0, "", "", errors.New("image request: n must be >= 1")
	}
	return n, raw.Size, raw.Quality, nil
}

// streamableRequest checks a JSON body for `"stream": true` without fully
// typing the request. Returns true only if the field is explicitly true.
func streamableRequest(body []byte) bool {
	var peek struct {
		Stream *bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &peek); err != nil {
		return false
	}
	return peek.Stream != nil && *peek.Stream
}

// handleChatCompletions dispatches to streaming or non-streaming based on
// the request body.
func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	s.dispatchStreamable(w, r, endpointChatCompletions)
}

func (s *Server) handleResponses(w http.ResponseWriter, r *http.Request) {
	s.dispatchStreamable(w, r, endpointResponses)
}

func (s *Server) handleImageGeneration(w http.ResponseWriter, r *http.Request) {
	s.dispatchStreamable(w, r, endpointImages)
}

func (s *Server) handleImageEdits(w http.ResponseWriter, r *http.Request) {
	s.dispatchStreamable(w, r, endpointImageEdits)
}

// parseImageEditMultipart reads the `model` and `n` form fields and
// confirms the binary `image` part is present, without consuming the
// byte buffer (the proxy reseals the same bytes into the envelope, so
// the input must not be mutated). The boundary comes from the
// request's Content-Type header — the proxy is the only point in the
// pipeline that still has it (the envelope strips it on the way to
// the node).
//
// Trust model: the inbound Content-Type (and thus the boundary) is
// NOT covered by the envelope's AAD or admission tag — only the body
// bytes are. A malicious peer that rewrites Content-Type in flight
// would cause this parser to fail-closed (parse error → 400), so
// proxy/node parsing cannot desync; the node re-sniffs the boundary
// from the body itself.
//
// Defaults n to 1 when omitted; rejects n < 1. The model field and
// the binary `image` part are required — image-edits is per-model
// billed (proxy can't route without `model`) and the request is
// meaningless without an image (we reject up front so a malformed
// client doesn't burn an operator reserve).
func parseImageEditMultipart(contentType string, body []byte) (model string, n int, size, quality string, stream bool, err error) {
	if contentType == "" {
		return "", 0, "", "", false, errors.New("multipart Content-Type header is required")
	}
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", 0, "", "", false, fmt.Errorf("parse Content-Type: %w", err)
	}
	boundary := params["boundary"]
	if boundary == "" {
		return "", 0, "", "", false, errors.New("multipart boundary missing from Content-Type")
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	n = 1
	sawImage := false
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", 0, "", "", false, fmt.Errorf("read multipart: %w", err)
		}
		switch part.FormName() {
		case "image":
			sawImage = true
			_, _ = io.Copy(io.Discard, part)
		case "model":
			b, err := io.ReadAll(part)
			if err != nil {
				_ = part.Close()
				return "", 0, "", "", false, fmt.Errorf("read model field: %w", err)
			}
			model = string(b)
		case "n":
			b, err := io.ReadAll(part)
			if err != nil {
				_ = part.Close()
				return "", 0, "", "", false, fmt.Errorf("read n field: %w", err)
			}
			if v := string(b); v != "" {
				parsed, err := strconv.Atoi(v)
				if err != nil {
					_ = part.Close()
					return "", 0, "", "", false, fmt.Errorf("n: %w", err)
				}
				n = parsed
			}
		case "size":
			b, err := io.ReadAll(part)
			if err != nil {
				_ = part.Close()
				return "", 0, "", "", false, fmt.Errorf("read size field: %w", err)
			}
			size = string(b)
		case "quality":
			b, err := io.ReadAll(part)
			if err != nil {
				_ = part.Close()
				return "", 0, "", "", false, fmt.Errorf("read quality field: %w", err)
			}
			quality = string(b)
		case "stream":
			// Transport-only hint (OpenAI-compatible): the caller wants the
			// response streamed. Drives the proxy's wantsStream decision; the
			// same `stream` form field reaches the node, which reads it too.
			b, err := io.ReadAll(part)
			if err != nil {
				_ = part.Close()
				return "", 0, "", "", false, fmt.Errorf("read stream field: %w", err)
			}
			if v := string(b); v == "true" || v == "1" {
				stream = true
			}
		default:
			_, _ = io.Copy(io.Discard, part)
		}
		_ = part.Close()
	}
	if model == "" {
		return "", 0, "", "", false, errors.New("model field is required")
	}
	if !sawImage {
		return "", 0, "", "", false, errors.New("image part is required")
	}
	if n < 1 {
		return "", 0, "", "", false, fmt.Errorf("n must be >= 1, got %d", n)
	}
	return model, n, size, quality, stream, nil
}

// modelsOwnedBy is the `owned_by` on every /v1/models entry: a model may be
// served by many operators, so no single one owns it here.
const modelsOwnedBy = "zerosignal"

// modelDetailsByID indexes the registry's model capability union by id, so the
// two model endpoints project the same aggregate onto the same wire shape.
//
// The id SET and its order come from AllModels, not from these keys: AllModels
// is the discovery contract (the union across *reachable* operators), while a
// details entry is capability info that a model may simply not have. A model in
// one and not the other must still be listed, bare.
func (s *Server) modelDetailsByID(ctx context.Context) map[string]inject.OperatorDetailsModel {
	byID := make(map[string]inject.OperatorDetailsModel)
	for _, d := range s.registryProvider.AllModelDetails(ctx) {
		byID[d.ID] = d
	}
	return byID
}

// modelEntryFor projects one advertised model onto the /v1/models entry shape,
// applying the corrections the shared builder cannot make because they hold for
// the proxy's cross-operator aggregate and not for a node's own catalog.
//
// **Rates are grossed up to payer-net.** /v1/zs/details publishes the
// operator's raw rate beside a top-level `fee_bps` so a consumer can gross it
// themselves — but OpenRouter's `pricing` object has no fee field, and its
// whole meaning is "this is what it costs". Publishing the pre-fee number in
// that shape understates every reader's cost by the protocol fee with no way to
// correct it. So this surface deliberately differs from /v1/zs/details for the
// same model: there the number is what the operator charges, here it is what
// the payer pays.
//
// **Anything short of a rate the proxy can stand behind publishes NO price.**
// The three cases share one rule, because on this surface a number is a claim
// and an absent object is not:
//
//   - feeKnown false. The fee cache is cold until the first read, which is why
//     Server.WarmFeeRate kicks that read at startup — an OpenAI-compatible
//     client fetches the catalog once, at connect time, and caches what it
//     gets, so without the warm the first client to connect is the one that
//     misses. The warm narrows that window rather than closing it (it does not
//     block), so this branch is still reachable and still must publish nothing.
//     Falling back to the raw rate here would publish the understated number
//     the gross-up exists to prevent, and unlike /v1/zs/details (which omits
//     `fee_bps` so a consumer knows to fall back) this shape has no field in
//     which to say so: a cold fee would be indistinguishable from a warm
//     zero-fee protocol.
//   - EITHER rate zero. AllModelDetails keeps the lowest *declared, non-zero*
//     rate across operators (proto/go/zs/registry.go), folding input and
//     output independently, so a zero on either side means nothing was declared
//     for it — equally the state of an operator whose capability probe hasn't
//     landed. Publishing the other side beside a "0" claims free prompt tokens
//     for a rate nobody set. Note the aggregate cannot express a genuinely free
//     model at all; a node can (one validated config, where an explicit 0 IS
//     free) and keeps its zeros, which is why this lives here and not in the
//     builder.
//   - The builder's own image-route carve-out, which drops Pricing before this
//     ever sees it.
func modelEntryFor(d inject.OperatorDetailsModel, grossFactor float64, feeKnown bool) inject.OpenAIModel {
	if grossFactor != 1 {
		d.InputRateUSDPer1M = grossRate(d.InputRateUSDPer1M, grossFactor)
		d.OutputRateUSDPer1M = grossRate(d.OutputRateUSDPer1M, grossFactor)
		if d.CacheReadRateUSDPer1M != nil {
			// A FRESH pointer. Both in-tree providers rebuild the aggregate per
			// call and allocate every rate pointer fresh (minRatePtr returns &v
			// on all branches), so nothing aliases today — but
			// OpenAIModelFromDetails documents its result as aliasing d, and a
			// provider that memoized the aggregate would make a write-through
			// gross up its own cache and compound on every request. The guard
			// costs one float; discovering it were needed would cost a payer a
			// wrong price.
			grossed := grossRate(*d.CacheReadRateUSDPer1M, grossFactor)
			d.CacheReadRateUSDPer1M = &grossed
		}
	}
	m := inject.OpenAIModelFromDetails(d, modelsOwnedBy, 0)
	if !feeKnown || d.InputRateUSDPer1M == 0 || d.OutputRateUSDPer1M == 0 {
		m.Pricing = nil
	}
	return m
}

// grossFactorNow turns an operator's advertised rate into the payer-net rate:
// the payer pays rate × (1 + feeBps/BpsDenominator), the fee riding on top of
// amount_charged (mirrors escrow.NetFee and the client's cost display).
//
// ok=false means the fee is not known — a cold cache, an algod that has never
// answered, or a wallet with no fee capability. Callers must publish no price
// at all in that state rather than fall back to the raw rate; see modelEntryFor.
func (s *Server) grossFactorNow() (factor float64, ok bool) {
	feeBps, ok := s.feeRateNow()
	if !ok {
		return 1, false
	}
	return 1 + float64(feeBps)/float64(escrow.BpsDenominator), true
}

// grossRate is the twin of internal/connect.grossRate — same rounding, to the
// microUSDC the rate is ultimately denominated in, so the two paths publish the
// same number for the same model. Pinned by TestGrossRate.
//
// A non-finite result becomes 0, which modelEntryFor's zero rule then turns
// into no price at all. The rate is a remote operator's unvalidated
// advertisement, and one above ~1.8e302 overflows the multiply to +Inf — which
// usdPerToken renders as "0", i.e. an affirmative claim of FREE. Collapsing to
// 0 here routes an absurd rate to "unknown", the one honest answer.
func grossRate(usdPer1M, grossFactor float64) float64 {
	out := math.Round(usdPer1M*grossFactor*1e6) / 1e6
	if math.IsInf(out, 0) || math.IsNaN(out) {
		return 0
	}
	return out
}

// handleListModels answers GET /v1/models from the on-chain registry.
//
// The entry shape is inject.OpenAIModel — OpenAI's four official fields (which
// carry no context window, pricing, or capability signal at all) plus the
// OpenRouter-shaped fields any client reading past `id` actually parses. Every
// value is the cross-operator UNION the registry already computes: sizing is
// the MINIMUM across declaring operators, so `context_length` reads as a floor
// rather than as one operator's terms. See modelEntryFor for what happens to
// the rates. The authoritative per-request price is the microUSDC the chosen
// node signs into the reserve ticket.
func (s *Server) handleListModels(w http.ResponseWriter, r *http.Request) {
	out := inject.NewOpenAIModelList(0)
	if s.registryProvider != nil {
		models := s.registryProvider.AllModels(r.Context())
		byID := s.modelDetailsByID(r.Context())
		grossFactor, feeKnown := s.grossFactorNow()
		out = inject.NewOpenAIModelList(len(models))
		for _, id := range models {
			d, ok := byID[id]
			if !ok {
				// Reachable through a third-party RegistryProvider, or in the
				// microseconds-wide window where a background refresh swaps the
				// snapshot between the two aggregate reads. Listing the id bare
				// is the same answer the get endpoint gives for it.
				d = inject.OperatorDetailsModel{ID: id}
			}
			out.Data = append(out.Data, modelEntryFor(d, grossFactor, feeKnown))
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// handleHayaiDetails surfaces the aggregate hayai capability view across
// every operator in the registry. The response shape mirrors the node's
// own /v1/zs/details so clients (TUI, SDKs) can decode either endpoint
// with the same struct.
//
// builtin_tools is the deduplicated union across operators. models is the
// deduplicated union of model capability info (modalities, sizing).
// Per-operator-only fields (operator_id, age pubkey, oracle health,
// max_tool_iterations) are intentionally omitted: they're per-node
// settlement state and have no clean aggregate meaning at the proxy.
func (s *Server) handleHayaiDetails(w http.ResponseWriter, r *http.Request) {
	type builtinToolEntry struct {
		Type string `json:"type"`
	}
	type modelEntry struct {
		ID               string   `json:"id"`
		ContextWindow    uint64   `json:"context_window,omitempty"`
		MaxOutputTokens  uint64   `json:"max_output_tokens,omitempty"`
		InputModalities  []string `json:"input_modalities,omitempty"`
		OutputModalities []string `json:"output_modalities,omitempty"`
		// Reasoning / ToolUse are the aggregated capability signals (OR
		// across operators — most-capable wins; DefaultEffort is dropped
		// from the aggregate since a single default has no cross-operator
		// meaning). nil = no reachable operator advertised the capability,
		// which is distinct from an explicit {Supported:false} / false.
		// Consumed by `zs-proxy connect` to fill in per-model capability
		// flags in the tools it configures. Advisory.
		Reasoning *inject.ModelReasoning `json:"reasoning,omitempty"`
		ToolUse   *bool                  `json:"tool_use,omitempty"`
		// USD/1M rates aggregated from operators (lowest declared rate
		// wins — see AllModelDetails). 0 means no operator declared a
		// rate for this model. Authoritative per-request rate is the
		// microUSDC value the chosen operator's node signs into the
		// reserve ticket; this is the advertising surface only.
		InputUSDPer1M  float64 `json:"input_usd_per_1m,omitempty"`
		OutputUSDPer1M float64 `json:"output_usd_per_1m,omitempty"`
		// CacheReadUSDPer1M is the lowest advertised cache-read discount
		// across operators serving this model ("from $X", same semantics as
		// the token rates). *float64: nil = no operator discounts cached
		// reads (field omitted); a pointed-to 0 = free cached reads (the
		// maximum discount, kept distinct from nil). Advertising surface
		// only — the authoritative per-request rate is signed into the ticket.
		CacheReadUSDPer1M *float64 `json:"cache_read_usd_per_1m,omitempty"`
		// Long-context (surcharge) tier aggregated across operators: the lowest
		// advertised threshold and the lowest of each high rate ("from $X", same
		// semantics as the token rates). Threshold 0 / nil rates = no reachable
		// operator advertised a tier. The high cache-read rate follows
		// CacheReadUSDPer1M's nil-vs-zero rule. Note the aggregate JSON style
		// (input_usd_per_1m, no _rate_) — the tier fields match it. Advertising
		// surface only — the authoritative per-request rates are signed into the ticket.
		LongContextThresholdTokens   uint64   `json:"long_context_threshold_tokens,omitempty"`
		LongContextInputUSDPer1M     *float64 `json:"long_context_input_usd_per_1m,omitempty"`
		LongContextOutputUSDPer1M    *float64 `json:"long_context_output_usd_per_1m,omitempty"`
		LongContextCacheReadUSDPer1M *float64 `json:"long_context_cache_read_usd_per_1m,omitempty"`
		// Per-image microUSDC rates aggregated across operators (lowest
		// non-zero value wins — same "from $X" semantics as the token rates).
		// ServesImageGen / ServesImageEdit are the price-independent "this
		// model is wired for /v1/images/{generations,edits}" signal (a
		// deliberately-free route advertises a 0 rate); clients gate the image
		// commands on these instead of inferring from output_modalities, which
		// can't distinguish gen-only vs edit-only models.
		ImageRateMicroUSDC     uint64 `json:"image_rate_micro_usdc,omitempty"`
		ImageEditRateMicroUSDC uint64 `json:"image_edit_rate_micro_usdc,omitempty"`
		ServesImageGen         bool   `json:"serves_image_gen,omitempty"`
		ServesImageEdit        bool   `json:"serves_image_edit,omitempty"`
		// Display companions to the dedicated rates above: the price a caller
		// who sends no size/quality actually pays (the rate resolved through the
		// operator's default_size) and the ceiling its max_size imposes. A
		// client renders default→cap as a range. Both absent when no operator
		// declares those knobs, where the rate is the whole story.
		ImageDefaultMicroUSDC     uint64 `json:"image_default_micro_usdc,omitempty"`
		ImageEditDefaultMicroUSDC uint64 `json:"image_edit_default_micro_usdc,omitempty"`
		ImageCapMicroUSDC         uint64 `json:"image_cap_micro_usdc,omitempty"`
		ImageEditCapMicroUSDC     uint64 `json:"image_edit_cap_micro_usdc,omitempty"`
		// Tool-path siblings: the per-image microUSDC cap of the
		// zs_image_generation / zs_image_edit built-in tools on a chat
		// model, and the representative price at the operator's default size.
		// Separate from ImageRateMicroUSDC so a chat model offering the
		// tools is never gated as a dedicated image-route model. Echoed for
		// completeness; clients enable the tools via builtin_tools, not these.
		ImageToolRateMicroUSDC     uint64 `json:"image_tool_rate_micro_usdc,omitempty"`
		ImageEditToolRateMicroUSDC uint64 `json:"image_edit_tool_rate_micro_usdc,omitempty"`
		ImageToolBaseMicroUSDC     uint64 `json:"image_tool_base_micro_usdc,omitempty"`
		ImageEditToolBaseMicroUSDC uint64 `json:"image_edit_tool_base_micro_usdc,omitempty"`
		// Coordinates is the per-field MAJORITY model taxonomy across operators
		// (AllModelDetails omits a field when operators disagree). Lean signal
		// only — the HF-discovered deep coordinates are per-node and never
		// aggregated. Advisory.
		Coordinates *inject.ModelCoordinates `json:"coordinates,omitempty"`
		// WeightsDigest is the cross-operator CONSENSUS weights digest (the
		// single "sha256:<hex>" when every verifiable operator agrees; omitted
		// on mismatch or when none published one). WeightsMismatch flags ≥2
		// distinct digests among the operators serving this id ("weights
		// differ"). Lean aggregate only — the per-node ?expand=digest detail is
		// never aggregated. Advisory; never gates routing/settlement. See
		// SPEC §3c (?expand=digest).
		WeightsDigest   string `json:"weights_digest,omitempty"`
		WeightsMismatch bool   `json:"weights_mismatch,omitempty"`
	}
	type detailsResp struct {
		Models       []modelEntry       `json:"models,omitempty"`
		BuiltinTools []builtinToolEntry `json:"builtin_tools"`
		// NodeVersions is the deduped set of build ids advertised by every
		// reachable operator. Surfaced so dashboards and the TUI can see
		// which builds are deployed without probing each node
		// individually. Omitted when no operator has reported one yet.
		//
		// BYTE-sorted, not version-ordered — sorting is here for
		// deterministic output only. Now that a build id leads with a
		// release name, "0.21.0+…" sorts ahead of "0.9.0+…", so a consumer
		// rendering this in order must not present it as a version ladder.
		NodeVersions []string `json:"node_versions,omitempty"`
		// FeeBps is the proxy payer's effective protocol fee (basis points),
		// read from the contract's protocolFeeBps global. Surfaced so discovery
		// consumers (e.g. `zs-proxy connect`, which grosses the advertised
		// operator rates up to payer-net) can estimate spend without a chain
		// read of their own. Omitted when the fee cache hasn't warmed yet →
		// consumers fall back to the raw operator rates. Advertising surface
		// only: the authoritative fee is snapshotted onto the ticket at open().
		FeeBps uint64 `json:"fee_bps,omitempty"`
	}
	out := detailsResp{BuiltinTools: []builtinToolEntry{}}
	if feeBps, ok := s.feeRateNow(); ok {
		out.FeeBps = feeBps
	}
	if s.registryProvider != nil {
		for _, d := range s.registryProvider.AllModelDetails(r.Context()) {
			out.Models = append(out.Models, modelEntry{
				ID:                           d.ID,
				ContextWindow:                d.ContextWindow,
				MaxOutputTokens:              d.MaxOutputTokens,
				InputModalities:              d.InputModalities,
				OutputModalities:             d.OutputModalities,
				Reasoning:                    d.Reasoning,
				ToolUse:                      d.ToolUse,
				InputUSDPer1M:                d.InputRateUSDPer1M,
				OutputUSDPer1M:               d.OutputRateUSDPer1M,
				CacheReadUSDPer1M:            d.CacheReadRateUSDPer1M,
				LongContextThresholdTokens:   d.LongContextThresholdTokens,
				LongContextInputUSDPer1M:     d.LongContextInputRateUSDPer1M,
				LongContextOutputUSDPer1M:    d.LongContextOutputRateUSDPer1M,
				LongContextCacheReadUSDPer1M: d.LongContextCacheReadRateUSDPer1M,
				ImageRateMicroUSDC:           d.ImageRateMicroUSDC,
				ImageEditRateMicroUSDC:       d.ImageEditRateMicroUSDC,
				ImageDefaultMicroUSDC:        d.ImageDefaultMicroUSDC,
				ImageEditDefaultMicroUSDC:    d.ImageEditDefaultMicroUSDC,
				ImageCapMicroUSDC:            d.ImageCapMicroUSDC,
				ImageEditCapMicroUSDC:        d.ImageEditCapMicroUSDC,
				ServesImageGen:               d.ServesImageGen,
				ServesImageEdit:              d.ServesImageEdit,
				ImageToolRateMicroUSDC:       d.ImageToolRateMicroUSDC,
				ImageEditToolRateMicroUSDC:   d.ImageEditToolRateMicroUSDC,
				ImageToolBaseMicroUSDC:       d.ImageToolBaseMicroUSDC,
				ImageEditToolBaseMicroUSDC:   d.ImageEditToolBaseMicroUSDC,
				Coordinates:                  d.Coordinates,
				WeightsDigest:                d.WeightsDigest,
				WeightsMismatch:              d.WeightsMismatch,
			})
		}
		for _, t := range s.registryProvider.AllBuiltinTools(r.Context()) {
			out.BuiltinTools = append(out.BuiltinTools, builtinToolEntry{Type: t.Type})
		}
		out.NodeVersions = s.registryProvider.AllNodeVersions(r.Context())
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// handleHayaiOperators surfaces the per-operator view of the registry:
// every operator the proxy currently knows about, with its own model
// list, capabilities, reachability, and TEE verdict. Complements the
// aggregated /v1/zs/details by *not* unioning across operators —
// downstream clients (TUI, dashboards) use this to render which
// operator backs which model and to surface per-node deployment
// detail (build version, owner address, attestation).
//
// Every field is already public:
//   - operator_id, owner_addr, signing_addr come from the on-chain
//     ZeroSignalEscrow OperatorRecord.
//   - metrics is the on-chain reliability track record (per-operator
//     ticket counters, dispute exposure, latency aggregates, lifetime +
//     windowed revenue) read verbatim from the OperatorRecord; see
//     proto/SPEC.md §3c. latency_mean_ms is derived (latency_total_ms /
//     settled population). Windowed revenue is computed at registry-load
//     time, so it's current to within one refresh interval.
//   - models, builtin_tools, node_version, max_tool_iterations come
//     from each operator's own /v1/zs/details probe.
//   - tee.{mode,verified} comes from the proxy's attestation verdict
//     (TEE.Verified mirrors the bit routing already filters on).
//
// AgeRecipient is intentionally omitted — also public, but no current
// consumer of this endpoint needs it.
//
// Staging nodes are held out unless the payer set zs.allow_staging, matching
// /v1/models and the aggregate /v1/zs/details — this is the directory the ids in
// a `provider` routing preference come from, so listing a node here that
// selection then refuses would offer an id that can never be honored. The filter
// is applied HERE rather than in AllOperators because the relay pool is built
// from that method and a staging node is still a valid relay hop; the accepted
// consequence is that a staging node the proxy is actively relaying through does
// not appear on this endpoint while the knob is off.
func (s *Server) handleHayaiOperators(w http.ResponseWriter, r *http.Request) {
	type modelEntry struct {
		ID               string   `json:"id"`
		ContextWindow    uint64   `json:"context_window,omitempty"`
		MaxOutputTokens  uint64   `json:"max_output_tokens,omitempty"`
		InputModalities  []string `json:"input_modalities,omitempty"`
		OutputModalities []string `json:"output_modalities,omitempty"`
		// USD/1M rates as advertised by this specific operator. 0 means
		// the operator did not declare a rate for the model. The node's
		// reserve handler resolves these (with default_pricing fallback)
		// when minting a ticket; the values surfaced here are the
		// pre-reserve advertising surface.
		InputUSDPer1M  float64 `json:"input_usd_per_1m,omitempty"`
		OutputUSDPer1M float64 `json:"output_usd_per_1m,omitempty"`
		// CacheReadUSDPer1M is THIS operator's advertised cache-read discount
		// verbatim (no cross-operator aggregation on the per-operator surface).
		// *float64: nil = no discount (omitted); a pointed-to 0 = free cached
		// reads. Advertising surface only.
		CacheReadUSDPer1M *float64 `json:"cache_read_usd_per_1m,omitempty"`
		// Per-image microUSDC rates this operator publishes for the model.
		// ServesImageGen / ServesImageEdit are the price-independent
		// /v1/images/{generations,edits} support signal (a deliberately-free
		// route advertises a 0 rate); clients gate the per-endpoint capability
		// on these (the symmetric "edit-only" and "gen-only" advertisements look
		// identical in output_modalities=[image] otherwise).
		ImageRateMicroUSDC     uint64 `json:"image_rate_micro_usdc,omitempty"`
		ImageEditRateMicroUSDC uint64 `json:"image_edit_rate_micro_usdc,omitempty"`
		ServesImageGen         bool   `json:"serves_image_gen,omitempty"`
		ServesImageEdit        bool   `json:"serves_image_edit,omitempty"`
		// Display companions — see the /v1/zs/details handler. This operator's
		// values verbatim, so default→cap describes exactly what IT charges.
		ImageDefaultMicroUSDC     uint64 `json:"image_default_micro_usdc,omitempty"`
		ImageEditDefaultMicroUSDC uint64 `json:"image_edit_default_micro_usdc,omitempty"`
		ImageCapMicroUSDC         uint64 `json:"image_cap_micro_usdc,omitempty"`
		ImageEditCapMicroUSDC     uint64 `json:"image_edit_cap_micro_usdc,omitempty"`
		// Tool-path siblings — see the /v1/zs/details handler.
		ImageToolRateMicroUSDC     uint64 `json:"image_tool_rate_micro_usdc,omitempty"`
		ImageEditToolRateMicroUSDC uint64 `json:"image_edit_tool_rate_micro_usdc,omitempty"`
		ImageToolBaseMicroUSDC     uint64 `json:"image_tool_base_micro_usdc,omitempty"`
		ImageEditToolBaseMicroUSDC uint64 `json:"image_edit_tool_base_micro_usdc,omitempty"`
		// Coordinates is THIS operator's lean model taxonomy verbatim (no
		// cross-operator aggregation on the per-operator surface — that's the
		// aggregate /v1/zs/details' job). Advisory.
		Coordinates *inject.ModelCoordinates `json:"coordinates,omitempty"`
		// WeightsDigest / WeightsUnverifiable are THIS operator's compact
		// weights-integrity signal verbatim (the per-operator surface never
		// aggregates). The verbose unverifiable-reason rides the node's own
		// ?expand=digest deep path, which the proxy doesn't probe. Advisory.
		WeightsDigest       string `json:"weights_digest,omitempty"`
		WeightsUnverifiable bool   `json:"weights_unverifiable,omitempty"`
		// Source / CanonicalID are THIS operator's model identity keys verbatim
		// (no aggregation here — the consensus rollup is the aggregate
		// /v1/zs/details' job). Source is the declared HF pointer; CanonicalID the
		// frontier canonical for a sourceless closed-weights model. Advisory.
		Source      string `json:"source,omitempty"`
		CanonicalID string `json:"canonical_id,omitempty"`
		// Retention is THIS operator's upstream data-retention tier for the
		// model — one of inject.Retention*, or absent for unknown, already
		// filtered through inject.IsKnownRetention on the way in so a node
		// cannot mint its own label here. Deliberately not aggregated across
		// operators, unlike Source / CanonicalID / WeightsDigest: those describe
		// the MODEL and a disagreement is information, while this describes each
		// operator's own deployment and operators SHOULD differ. Advisory.
		Retention string `json:"retention,omitempty"`
	}
	type builtinToolEntry struct {
		Type string `json:"type"`
	}
	type teeEntry struct {
		Mode     string `json:"mode,omitempty"`
		Verified bool   `json:"verified"`
		// No omitempty: null (no verified list) and [] (the node attested an
		// empty catalog) are different answers, and omitempty would collapse
		// both into an absent key.
		AttestedModelIDs []string `json:"attested_model_ids"`
	}
	// metricsEntry mirrors hayai.OperatorMetrics (itself a mirror of the
	// on-chain OperatorRecord reliability tail — proto/SPEC.md §3c).
	// All *_usdc values are microUSDC; *_ms values are milliseconds.
	type metricsEntry struct {
		LastActivityAt          uint64 `json:"last_activity_at"`
		TicketsOpened           uint64 `json:"tickets_opened"`
		TicketsSettled          uint64 `json:"tickets_settled"`
		TicketsLapsedSettled    uint64 `json:"tickets_lapsed_settled"`
		TicketsRefundedInactive uint64 `json:"tickets_refunded_inactive"`
		TicketsProtested        uint64 `json:"tickets_protested"`
		TicketsFrozenDispute    uint64 `json:"tickets_frozen_dispute"`

		TotalRefundedInactiveUsdc uint64 `json:"total_refunded_inactive_usdc"`
		TotalProtestedUsdc        uint64 `json:"total_protested_usdc"`
		TotalFrozenDisputeUsdc    uint64 `json:"total_frozen_dispute_usdc"`

		LatencyTotalMs uint64 `json:"latency_total_ms"`
		LatencyEwmaMs  uint64 `json:"latency_ewma_ms"`
		LatencySamples uint64 `json:"latency_samples"` // settles that folded a TTFT — the mean's denominator
		LatencyMeanMs  uint64 `json:"latency_mean_ms"` // derived: total / latency_samples

		TotalRevenueGrossUsdc uint64 `json:"total_revenue_gross_usdc"`
		TotalRevenueNetUsdc   uint64 `json:"total_revenue_net_usdc"`

		Revenue24hUsdc uint64 `json:"revenue_24h_usdc"`
		Revenue7dUsdc  uint64 `json:"revenue_7d_usdc"`
		Revenue30dUsdc uint64 `json:"revenue_30d_usdc"`
	}
	type operatorEntry struct {
		OperatorID uint64 `json:"operator_id"`
		// NodeID is the serving node within OperatorID (operator/node split): one
		// entry per running node, so the (operator_id, node_id) pair identifies it.
		// Omitted when zero — node ids are 1-based on-chain (0 is the unset
		// sentinel) — which also keeps the field absent on probes that predate it.
		NodeID      uint64 `json:"node_id,omitempty"`
		OwnerAddr   string `json:"owner_addr,omitempty"`
		SigningAddr string `json:"signing_addr,omitempty"`
		BaseURL     string `json:"base_url,omitempty"`
		NodeVersion string `json:"node_version,omitempty"`
		// ProtoVersion is the wire-protocol generation the operator
		// advertises (`proto_version` on /v1/zs/details — SPEC.md
		// §3c). Surfaced here so dashboards can spot wire-protocol
		// skew across the fleet alongside the existing build-version
		// skew shown by `node_version`. Empty on operators whose probe
		// hasn't landed or whose node pre-dates the field.
		ProtoVersion string `json:"proto_version,omitempty"`
		Reachable    bool   `json:"reachable"`
		// Staging is the node's on-chain NodeRecord.staging flag. A marker, not a
		// filter: the loop below drops held-out staging nodes outright, so this can
		// only ever be true when the payer opted in via zs.allow_staging — it exists
		// so a consumer that opted in can still tell the two apart (the operator
		// dashboard badges them the same way). bool + omitempty matches
		// selection.Operator.Staging and the persisted catalog field.
		Staging           bool      `json:"staging,omitempty"`
		TEE               *teeEntry `json:"tee,omitempty"`
		MaxToolIterations int       `json:"max_tool_iterations,omitempty"`
		// Per-request minimum charge advertised on /v1/zs/details
		// (SPEC.md §3a "Minimum charge"). MinChargeOutputTokens is the
		// reference output-token count for the per-model token
		// component (default 1000; 0/omitted = that component off).
		// MinChargeAlgoTxns / MinChargeMicroUSDC are the µALGO
		// component's count and current USD value (0/omitted when off
		// or the operator's oracle is unhealthy). The effective floor
		// for a model = max(ceil(MinChargeOutputTokens * model output
		// rate µUSDC/1M / 1e6), MinChargeMicroUSDC). Authoritative
		// per-request value lives on the signed ticket at reserve.
		MinChargeOutputTokens uint64             `json:"min_charge_output_tokens,omitempty"`
		MinChargeAlgoTxns     uint64             `json:"min_charge_algo_txns,omitempty"`
		MinChargeMicroUSDC    uint64             `json:"min_charge_microusdc,omitempty"`
		Metrics               metricsEntry       `json:"metrics"`
		Models                []modelEntry       `json:"models"`
		BuiltinTools          []builtinToolEntry `json:"builtin_tools"`
		// SignerSpendableMicroAlgos is the signing account's last-read spendable
		// ALGO (absent = never read), and SignerUnderfunded whether it is below
		// the routing floor. Unlike staging, an underfunded node stays LISTED:
		// the condition is transient and has no payer-side knob, so this is the
		// one place a payer can see why a node's models left the catalog — the
		// same reasoning that keeps wire-incompatible nodes listed.
		SignerSpendableMicroAlgos *uint64 `json:"signer_spendable_microalgos,omitempty"`
		SignerUnderfunded         bool    `json:"signer_underfunded,omitempty"`
	}
	type listResponse struct {
		Operators []operatorEntry `json:"operators"`
	}

	out := listResponse{Operators: []operatorEntry{}}
	if s.registryProvider != nil {
		ops := s.registryProvider.AllOperators(r.Context())
		out.Operators = make([]operatorEntry, 0, len(ops))
		for _, op := range ops {
			if hayai.HeldOutStaging(op, s.cfg.AllowStaging) {
				continue
			}
			models := make([]modelEntry, 0, len(op.Models))
			for _, m := range op.Models {
				cap := op.ModelCapacities[m]
				models = append(models, modelEntry{
					ID:                         m,
					ContextWindow:              cap.ContextWindow,
					MaxOutputTokens:            cap.MaxOutputTokens,
					InputModalities:            cap.InputModalities,
					OutputModalities:           cap.OutputModalities,
					InputUSDPer1M:              cap.InputUSDPer1M,
					OutputUSDPer1M:             cap.OutputUSDPer1M,
					CacheReadUSDPer1M:          cap.CacheReadUSDPer1M,
					ImageRateMicroUSDC:         cap.ImageRateMicroUSDC,
					ImageEditRateMicroUSDC:     cap.ImageEditRateMicroUSDC,
					ImageDefaultMicroUSDC:      cap.ImageDefaultMicroUSDC,
					ImageEditDefaultMicroUSDC:  cap.ImageEditDefaultMicroUSDC,
					ImageCapMicroUSDC:          cap.ImageCapMicroUSDC,
					ImageEditCapMicroUSDC:      cap.ImageEditCapMicroUSDC,
					ServesImageGen:             cap.ServesImageGen(),
					ServesImageEdit:            cap.ServesImageEdit(),
					ImageToolRateMicroUSDC:     cap.ImageToolRateMicroUSDC,
					ImageEditToolRateMicroUSDC: cap.ImageEditToolRateMicroUSDC,
					ImageToolBaseMicroUSDC:     cap.ImageToolBaseMicroUSDC,
					ImageEditToolBaseMicroUSDC: cap.ImageEditToolBaseMicroUSDC,
					Coordinates:                cap.Coordinates,
					WeightsDigest:              cap.WeightsDigest,
					WeightsUnverifiable:        cap.WeightsUnverifiable,
					Source:                     cap.Source,
					CanonicalID:                cap.CanonicalID,
					Retention:                  cap.Retention,
				})
			}
			tools := make([]builtinToolEntry, 0, len(op.BuiltinTools))
			for _, t := range op.BuiltinTools {
				tools = append(tools, builtinToolEntry{Type: t.Type})
			}
			var tee *teeEntry
			if op.TEE != nil {
				tee = &teeEntry{Mode: op.TEE.Mode, Verified: op.TEE.Verified,
					AttestedModelIDs: op.TEE.AttestedModelIDs}
			}
			m := op.Metrics
			out.Operators = append(out.Operators, operatorEntry{
				OperatorID:            op.ID,
				NodeID:                op.NodeID,
				OwnerAddr:             op.OwnerAddr,
				SigningAddr:           op.SigningAddr,
				BaseURL:               op.BaseURL,
				NodeVersion:           op.NodeVersion,
				ProtoVersion:          op.ProtoVersion,
				Reachable:             op.Reachable,
				Staging:               op.Staging,
				TEE:                   tee,
				MaxToolIterations:     op.MaxToolIters,
				MinChargeOutputTokens: op.MinChargeOutputTokens,
				MinChargeAlgoTxns:     op.MinChargeAlgoTxns,
				MinChargeMicroUSDC:    op.MinChargeMicroUSDC,
				Metrics: metricsEntry{
					LastActivityAt:            m.LastActivityAt,
					TicketsOpened:             m.TicketsOpened,
					TicketsSettled:            m.TicketsSettled,
					TicketsLapsedSettled:      m.TicketsLapsedSettled,
					TicketsRefundedInactive:   m.TicketsRefundedInactive,
					TicketsProtested:          m.TicketsProtested,
					TicketsFrozenDispute:      m.TicketsFrozenDispute,
					TotalRefundedInactiveUsdc: m.TotalRefundedInactiveUsdc,
					TotalProtestedUsdc:        m.TotalProtestedUsdc,
					TotalFrozenDisputeUsdc:    m.TotalFrozenDisputeUsdc,
					LatencyTotalMs:            m.LatencyTotalMs,
					LatencyEwmaMs:             m.LatencyEwmaMs,
					LatencySamples:            m.LatencySamples,
					LatencyMeanMs:             m.LatencyMeanMs(),
					TotalRevenueGrossUsdc:     m.TotalRevenueGross,
					// Net == gross under the additive fee model (operator keeps
					// the full base; the payer pays the fee on top). The
					// dedicated net field is gone from the on-chain record; keep
					// the response field for API stability, mirroring gross.
					TotalRevenueNetUsdc: m.TotalRevenueGross,
					Revenue24hUsdc:      m.Revenue24hUsdc,
					Revenue7dUsdc:       m.Revenue7dUsdc,
					Revenue30dUsdc:      m.Revenue30dUsdc,
				},
				Models:                    models,
				BuiltinTools:              tools,
				SignerSpendableMicroAlgos: op.SignerSpendableMicroAlgos,
				SignerUnderfunded:         op.SignerUnderfunded(),
			})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// handleGetModel answers GET /v1/models/{id} from the on-chain registry.
// A 404 surfaces as the standard OpenAI envelope so SDK clients map it to
// model_not_found. The entry is byte-identical to the one the list endpoint
// emits for the same id — same aggregate, same builder — so a client can't
// learn different things about a model from the two surfaces.
//
// Membership is AllModels, not AllModelDetails: a model advertised with no
// capability info is still served, and answering 404 for it would contradict
// the list.
func (s *Server) handleGetModel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	notFound := func() {
		writeOpenAIError(w, http.StatusNotFound, "invalid_request_error", "model_not_found", "The model '"+id+"' does not exist or you do not have access to it.")
	}
	if id == "" {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "missing_model_id", "model id is required")
		return
	}
	if s.registryProvider == nil {
		notFound()
		return
	}
	if !slices.Contains(s.registryProvider.AllModels(r.Context()), id) {
		notFound()
		return
	}
	d, ok := s.modelDetailsByID(r.Context())[id]
	if !ok {
		// See the same branch in handleListModels: reachable only through a
		// third-party RegistryProvider or a snapshot swap between the two
		// aggregate reads. Answering bare keeps the two endpoints in agreement.
		d = inject.OperatorDetailsModel{ID: id}
	}
	w.Header().Set("Content-Type", "application/json")
	grossFactor, feeKnown := s.grossFactorNow()
	_ = json.NewEncoder(w).Encode(modelEntryFor(d, grossFactor, feeKnown))
}

// readClientBody buffers r.Body capped at MaxClientBodyBytes. On failure it
// writes an OpenAI-shaped error to w and returns ok=false; callers should
// return immediately in that case. A body that exceeds the cap becomes a
// 413 with code="body_too_large"; other read failures are 400.
func readClientBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	limited := http.MaxBytesReader(w, r.Body, MaxClientBodyBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			writeOpenAIError(w, http.StatusRequestEntityTooLarge, "invalid_request_error", "body_too_large", "request body exceeds proxy limit")
			return nil, false
		}
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "read_body", "failed to read request body")
		return nil, false
	}
	return body, true
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}

// dispatchStreamable is the entry point for endpoints whose request body
// may ask for a streaming response. It reads the client body once, then
// hands off to dispatchHayai, which decides stream vs non-stream itself.
func (s *Server) dispatchStreamable(w http.ResponseWriter, r *http.Request, endpoint string) {
	body, ok := readClientBody(w, r)
	if !ok {
		return
	}
	_ = r.Body.Close()
	s.dispatchHayai(w, r, endpoint, body, formatChat)
}
