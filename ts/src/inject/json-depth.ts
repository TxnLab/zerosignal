/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Go's encoding/json refuses a document nested deeper than maxNestingDepth
// (10000 arrays and objects) and JSON.parse has no limit, so a decoder that
// must refuse what Go refuses checks the depth first. Without it a node could
// pad its bundle with one deep unknown field and be refused by every Go payer
// while every TypeScript payer routed to it.

const GO_MAX_NESTING_DEPTH = 10000

/**
 * withinGoNestingDepth reports whether Go's scanner would accept text's
 * nesting. Exact for valid JSON; for invalid JSON the answer does not matter,
 * since JSON.parse refuses it next.
 */
export function withinGoNestingDepth(text: string): boolean {
  let depth = 0
  let inString = false
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    if (inString) {
      if (c === 0x5c) i++
      else if (c === 0x22) inString = false
    } else if (c === 0x22) {
      inString = true
    } else if (c === 0x5b || c === 0x7b) {
      if (++depth > GO_MAX_NESTING_DEPTH) return false
    } else if (c === 0x5d || c === 0x7d) {
      depth--
    }
  }
  return true
}
