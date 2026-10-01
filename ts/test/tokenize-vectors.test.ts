/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Cross-impl parity test for the reserve-sizing bound. Loads
// proto/testdata/tokenize_vectors.json (produced by
// proto/go/tokenize/vectors_test.go) and asserts the TypeScript port of
// inputTokenBound / reserveInputCount produces identical numbers. If this
// fails, the TS bound has drifted from the Go reference — which would desync
// the client reserve sizing from the node's inference-time budget check
// (→ input_budget_exceeded / cut-off). Sync both sides, then regenerate the
// vectors on the Go side.

import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'

import { inputTokenBound, inputTokenBoundV2, reserveInputCount } from '../src/tokenize/index.js'

interface InputBoundCase {
  name: string
  body_hex: string
  expected: number
  expected_v2: number
  // Marks a body where the two v1 implementations are KNOWN to disagree with
  // each other — a pre-existing defect left unfixed because v1 is the
  // compatibility floor every pre-9.2 peer computes. `expected` then records
  // only Go's value; `expected_v2` stays a strict parity contract. See the Go
  // generator's v1DivergentBodies for the specifics.
  v1_divergent?: boolean
}

// Corpus entries reference proto/testdata/tokenize_corpus/<sample>.json rather
// than inlining hex: the samples run to tens of kilobytes of real PNG/JPEG/WebP
// payloads. These are what cross-check the image header parser — a format whose
// dimensions one implementation reads and the other doesn't fails here rather
// than as rejected requests in production.
interface CorpusBoundCase {
  sample: string
  expected: number
  expected_v2: number
}

interface ReserveInputCountCase {
  name: string
  body_bound: number
  carries_tools: boolean
  max_tool_iterations: number
  per_iter_headroom: number
  max_output: number
  context_window: number
  floor: number
  expected: number
}

interface TokenizeVectorsFile {
  version: number
  comment: string
  input_token_bound: InputBoundCase[]
  corpus_bound: CorpusBoundCase[]
  reserve_input_count: ReserveInputCountCase[]
}

const here = path.dirname(fileURLToPath(import.meta.url))
const vectorsPath = path.resolve(here, '..', '..', 'testdata', 'tokenize_vectors.json')
const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf-8')) as TokenizeVectorsFile
const corpusDir = path.resolve(here, '..', '..', 'testdata', 'tokenize_corpus')

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

describe('cross-impl tokenize vectors (proto/testdata/tokenize_vectors.json)', () => {
  it('vectors file is current schema', () => {
    expect(vectors.version).toBe(2)
    expect(vectors.input_token_bound.length).toBeGreaterThan(0)
    expect(vectors.corpus_bound.length).toBeGreaterThan(0)
    expect(vectors.reserve_input_count.length).toBeGreaterThan(0)
  })

  for (const c of vectors.input_token_bound) {
    it(`inputTokenBound: ${c.name}`, { skip: c.v1_divergent === true }, () => {
      expect(inputTokenBound(hexToBytes(c.body_hex))).toBe(c.expected)
    })
    it(`inputTokenBoundV2: ${c.name}`, () => {
      expect(inputTokenBoundV2(hexToBytes(c.body_hex))).toBe(c.expected_v2)
    })
  }

  for (const c of vectors.corpus_bound) {
    it(`corpus bounds: ${c.sample}`, () => {
      const body = new Uint8Array(fs.readFileSync(path.join(corpusDir, `${c.sample}.json`)))
      expect(inputTokenBound(body), 'v1 drifted from the Go reference').toBe(c.expected)
      expect(inputTokenBoundV2(body), 'v2 drifted from the Go reference').toBe(c.expected_v2)
    })
  }

  for (const c of vectors.reserve_input_count) {
    it(`reserveInputCount: ${c.name}`, () => {
      expect(
        reserveInputCount({
          bodyBound: c.body_bound,
          carriesTools: c.carries_tools,
          maxToolIterations: c.max_tool_iterations,
          perIterHeadroom: c.per_iter_headroom,
          maxOutput: c.max_output,
          contextWindow: c.context_window,
          floor: c.floor,
        }),
      ).toBe(c.expected)
    })
  }
})
