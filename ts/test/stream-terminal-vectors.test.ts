/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Cross-impl parity test for terminal-frame classification. Loads
// proto/testdata/stream_vectors.json (produced by
// proto/go/wire/stream_terminal_vectors_test.go) and asserts the TypeScript
// port of classifyStreamFrame agrees frame-for-frame.
//
// This is a payer-safety invariant, not a rendering one: a consumer that misses
// a terminal frame tears the stream down before the `zs-receipt` /
// `zs-settle-group` tail, so it never verifies the operator's charge and the
// ticket lapses into whatever was claimed. See SPEC.md § 5.3 "Consuming the
// settlement tail". If this fails, the client and the proxy have drifted on
// which frames end a stream — sync both sides, then regenerate on the Go side.

import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'

import { classifyStreamFrame, type StreamApi } from '../src/wire/index.js'

interface FrameCase {
  name: string
  api: StreamApi
  frame: string
  terminal: boolean
  error: boolean
  message: string
}

interface StreamVectorsFile {
  version: number
  comment: string
  frames: FrameCase[]
}

const here = path.dirname(fileURLToPath(import.meta.url))
const vectorsPath = path.resolve(here, '..', '..', 'testdata', 'stream_vectors.json')
const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf-8')) as StreamVectorsFile

describe('cross-impl stream-terminal vectors (proto/testdata/stream_vectors.json)', () => {
  it('vectors file is current schema', () => {
    expect(vectors.version).toBe(1)
    expect(vectors.frames.length).toBeGreaterThan(0)
  })

  for (const c of vectors.frames) {
    it(`classifyStreamFrame [${c.api}]: ${c.name}`, () => {
      expect(classifyStreamFrame(c.frame, c.api)).toEqual({
        terminal: c.terminal,
        error: c.error,
        message: c.message,
      })
    })

    // The frames reach a real consumer as decrypted bytes, not strings — the
    // Uint8Array overload must agree with the string one or the client's
    // envelope layer and its tests would be testing different code.
    it(`classifyStreamFrame accepts bytes [${c.api}]: ${c.name}`, () => {
      const bytes = new TextEncoder().encode(c.frame)
      expect(classifyStreamFrame(bytes, c.api)).toEqual(classifyStreamFrame(c.frame, c.api))
    })
  }

  it('error implies terminal across every vector', () => {
    for (const c of vectors.frames) {
      if (c.error) expect(c.terminal).toBe(true)
    }
  })
})
