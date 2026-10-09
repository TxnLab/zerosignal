/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strconv"
)

// parseImageRequestN reads only the `n` field from an OpenAI
// /v1/images/generations request body. Defaults to 1 when omitted,
// rejects < 1. The model field is read separately via ExtractModel.
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
