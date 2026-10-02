/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package handler serves the OpenAI-compatible HTTP surface over the zs payer
// core: /v1/chat/completions, /v1/responses, the emulated /v1/completions,
// image generation and edits, model discovery, and /v1/zs/details.
//
// Each request is routed, reserved, paid for in escrow, sealed to the chosen
// node, and its signed receipt verified before the response is settled. zs-proxy
// is this package plus a CLI; its error remedies still name zs-proxy commands.
package handler
