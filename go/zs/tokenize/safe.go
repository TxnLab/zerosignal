/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tokenize

import (
	"encoding/json"

	prototokenize "github.com/TxnLab/zerosignal/go/tokenize"
)

// SafeEstimator is a model-agnostic upper-bound estimator. It does not know
// which tokenizer the model uses — it returns a count guaranteed not to
// underestimate any production BPE / SentencePiece vocabulary.
//
// The bound itself lives in the shared proto module and is NOT reimplemented
// here. It used to be: this file carried a byte-identical copy of the
// bytes-per-token walk and the image tile math, pinned to the proto version
// only by TestSafeEstimatorMatchesProto. That was tolerable while the bound was
// twenty lines; it stopped being so once the bound grew character-class run
// classification and an image header parser, where a copy is pure drift risk
// for no benefit. What remains here is the part that is genuinely proxy-shaped:
// reading max_output_tokens off the request body.
//
// BoundVersion selects which bound to use. The zero value means version 1 — the
// wire default, and the only bound a pre-9.2 node can reproduce. Dispatch sizes
// per-operator (see boundVersionFor) rather than reading this field; it exists
// so a test or a future flat-configured path can pin a version.
type SafeEstimator struct {
	BoundVersion uint8
}

// Estimate computes the input-token bound over the request body and reads
// max_output_tokens from whichever of the three OpenAI field names the body
// uses. Errors only when the body's max-output field is malformed JSON.
func (s SafeEstimator) Estimate(req Request) (Estimate, error) {
	maxOut, err := extractMaxOutput(req.Body)
	if err != nil {
		return Estimate{}, err
	}
	return Estimate{
		InputTokens:     prototokenize.InputTokenBoundVersion(req.Body, s.BoundVersion),
		MaxOutputTokens: maxOut,
	}, nil
}

// extractMaxOutput reads max_completion_tokens / max_tokens / max_output_tokens
// from the body, returning the first one set. The three names cover Chat
// Completions (both old `max_tokens` and new `max_completion_tokens`),
// the Responses API (`max_output_tokens`), and the legacy completions
// endpoint (`max_tokens`). Returns 0 with no error when none is set —
// the Registry's default kicks in one layer up.
func extractMaxOutput(body []byte) (uint64, error) {
	if len(body) == 0 {
		return 0, nil
	}
	var peek struct {
		MaxTokens           *uint64 `json:"max_tokens"`
		MaxCompletionTokens *uint64 `json:"max_completion_tokens"`
		MaxOutputTokens     *uint64 `json:"max_output_tokens"`
	}
	if err := json.Unmarshal(body, &peek); err != nil {
		return 0, err
	}
	switch {
	case peek.MaxCompletionTokens != nil && *peek.MaxCompletionTokens > 0:
		return *peek.MaxCompletionTokens, nil
	case peek.MaxOutputTokens != nil && *peek.MaxOutputTokens > 0:
		return *peek.MaxOutputTokens, nil
	case peek.MaxTokens != nil && *peek.MaxTokens > 0:
		return *peek.MaxTokens, nil
	}
	return 0, nil
}
