/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Cross-impl parity test for the reserve tool-loop-headroom classification.
// Loads proto/testdata/tool_growth_vectors.json (produced by
// proto/go/inject/toolgrowth_vectors_test.go) and asserts the TypeScript port
// of bodyDrivesServerSideToolGrowth / classifyToolEntry / normalizeToolName
// produces identical answers.
//
// If this fails, the client and the proxy have started sizing tool headroom
// differently for the same request — the exact bug this predicate was mirrored
// to fix. Sync both sides, then regenerate the vectors on the Go side.

import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  bodyDrivesServerSideToolGrowth,
  classifyToolEntry,
  normalizeToolName,
} from '../src/inject/index.js'

interface GrowthCase {
  name: string
  body: string
  expected: boolean
  why: string
}

interface ClassifyCase {
  name: string
  entry: string
  want_name: string
  want_class: string
}

interface ToolGrowthVectorsFile {
  version: number
  comment: string
  body_drives_server_side_tool_growth: GrowthCase[]
  classify_tool_entry: ClassifyCase[]
  normalize_tool_name: Record<string, string>
}

const here = path.dirname(fileURLToPath(import.meta.url))
const vectorsPath = path.resolve(here, '..', '..', 'testdata', 'tool_growth_vectors.json')
const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf-8')) as ToolGrowthVectorsFile

describe('cross-impl tool-growth vectors (proto/testdata/tool_growth_vectors.json)', () => {
  it('vectors file is current schema', () => {
    expect(vectors.version).toBe(1)
    expect(vectors.body_drives_server_side_tool_growth.length).toBeGreaterThan(0)
    expect(vectors.classify_tool_entry.length).toBeGreaterThan(0)
    expect(Object.keys(vectors.normalize_tool_name).length).toBeGreaterThan(0)
  })

  it('exercises both outcomes', () => {
    const cases = vectors.body_drives_server_side_tool_growth
    expect(cases.some((c) => c.expected)).toBe(true)
    expect(cases.some((c) => !c.expected)).toBe(true)
  })

  for (const c of vectors.body_drives_server_side_tool_growth) {
    it(`bodyDrivesServerSideToolGrowth: ${c.name} (${c.why})`, () => {
      expect(bodyDrivesServerSideToolGrowth(c.body)).toBe(c.expected)
    })
  }

  for (const c of vectors.classify_tool_entry) {
    it(`classifyToolEntry: ${c.name}`, () => {
      const got = classifyToolEntry(JSON.parse(c.entry))
      expect(got.name).toBe(c.want_name)
      expect(got.class).toBe(c.want_class)
    })
  }

  for (const [input, want] of Object.entries(vectors.normalize_tool_name)) {
    it(`normalizeToolName: ${JSON.stringify(input)}`, () => {
      expect(normalizeToolName(input)).toBe(want)
    })
  }
})
