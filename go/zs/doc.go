/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package zs is the ZeroSignal payer SDK: discovery, routing, reserve, escrow
// open/settle/protest/refund, sealing, relay hops, streaming, receipt checks
// and retry, between "I have a prompt and a funded account" and "I have the
// answer and a verified receipt".
//
// Applications keep presentation, key custody and spending policy. The SDK
// reads no environment: every setting arrives through Config, and every
// stateful routing signal sits behind a store interface with an in-memory
// default, so a long-running process can persist what a short one forgets.
//
// The API is v0 until the TypeScript client runs on its twin,
// @txnlab/zerosignal; names and semantics are shared with it, signatures are
// idiomatic to each language.
package zs
