/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Corpus tests for bound version 2 — the TS half of
// proto/go/tokenize/corpus_test.go, over the identical corpus and fixture.
//
// v2 changes exactly one thing relative to v1: images are priced from their true
// pixel dimensions instead of a flat 2048x2048 fallback. The text term is
// byte-identical to v1. These tests pin both halves of that claim, and record
// what v2 does NOT fix, so a green suite isn't mistaken for broader safety.
//
// See the Go file's header for why the text term is not tightened here: an
// earlier draft calibrated a run classifier against this very corpus and
// asserted safety over the same samples the constants were fitted to, which
// proved nothing — a holdout set found under-counts up to 3x.

import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  inputTokenBound,
  inputTokenBoundV2,
  inputTokenBoundVersion,
  supportedBoundVersion,
  BOUND_VERSION_1,
  BOUND_VERSION_2,
} from '../src/tokenize/index.js'

interface CorpusSample {
  name: string
  body_bytes: number
  messages: number
  image_tokens: number
  tokens: Record<string, number>
  real_tokens: number
}

interface CorpusFile {
  version: number
  comment: string
  tokenizers: string[]
  samples: CorpusSample[]
}

const here = path.dirname(fileURLToPath(import.meta.url))
const corpusDir = path.resolve(here, '../../testdata/tokenize_corpus')
const corpusFile = path.resolve(here, '../../testdata/tokenize_corpus.json')

/** 2048x2048 high detail — what an image with unknowable dimensions costs. */
const IMAGE_FALLBACK_TOKENS = 85 + 170 * 16

const corpus: CorpusFile = JSON.parse(fs.readFileSync(corpusFile, 'utf8'))

function sampleBody(name: string): Uint8Array {
  return new Uint8Array(fs.readFileSync(path.join(corpusDir, `${name}.json`)))
}

const isImageSample = (name: string) => name.startsWith('image_')

describe('v2 matches v1 on text', () => {
  // The core invariant of the image-only design. If this fails someone has
  // reintroduced a text-term change, which needs holdout methodology rather
  // than a corpus re-run.
  const textSamples = corpus.samples.filter((s) => !isImageSample(s.name))

  it('has text-only samples to check', () => {
    expect(textSamples.length).toBeGreaterThan(0)
  })

  for (const s of textSamples) {
    it(`${s.name}`, () => {
      const body = sampleBody(s.name)
      expect(
        inputTokenBoundV2(body),
        'v2 must not alter the text term',
      ).toBe(inputTokenBound(body))
    })
  }
})

describe('v2 never underestimates on images', () => {
  for (const s of corpus.samples.filter((x) => isImageSample(x.name))) {
    it(`${s.name}: bound >= real (${s.real_tokens})`, () => {
      const got = inputTokenBoundV2(sampleBody(s.name))
      expect(
        got,
        `${s.name}: bound ${got} < real ${s.real_tokens} — the payer under-reserves ` +
          `and the operator eats the difference`,
      ).toBeGreaterThanOrEqual(s.real_tokens)
    })
  }
})

describe('image dimensions are read from the data URL', () => {
  // GIF is deliberately absent: its Logical Screen Descriptor is payer-controlled
  // and is not the size a decoder reports.
  const cases: Array<[string, number, number]> = [
    ['image_png_512', 512, 512],
    ['image_png_1024x768', 1024, 768],
    ['image_jpeg_800x600', 800, 600],
    ['image_jpeg_big_exif', 640, 480],
    ['image_webp_vp8x', 1600, 1200],
    ['image_webp_vp8', 900, 700],
    ['image_webp_vp8l', 1280, 720],
  ]

  for (const [sample, w, h] of cases) {
    it(`${sample} (${w}x${h})`, () => {
      const wantImage = 85 + 170 * Math.ceil(w / 512) * Math.ceil(h / 512)
      const got = inputTokenBoundV2(sampleBody(sample))
      expect(got).toBeGreaterThanOrEqual(wantImage)
      if (wantImage < IMAGE_FALLBACK_TOKENS) {
        expect(got, 'dimensions were not read — still at the fallback').toBeLessThan(
          IMAGE_FALLBACK_TOKENS,
        )
      }
    })
  }

  for (const sample of [
    'image_remote_url',
    'image_truncated_png',
    'image_garbage_dataurl',
    'image_gif_320x240',
  ]) {
    it(`${sample} falls back HIGH`, () => {
      expect(inputTokenBoundV2(sampleBody(sample))).toBeGreaterThanOrEqual(IMAGE_FALLBACK_TOKENS)
    })
  }
})

describe('v2 fixes the large-image under-count', () => {
  // v1's flat 2048x2048 fallback UNDER-charges anything bigger. This is why v2
  // is not uniformly smaller than v1 and why the version is explicit on the wire.
  it('image_png_4096', () => {
    const body = sampleBody('image_png_4096')
    const v1 = inputTokenBound(body)
    const v2 = inputTokenBoundV2(body)
    const wantImage = 85 + 170 * 64
    expect(v1, 'v1 no longer under-charges a 4096px image').toBeLessThan(wantImage)
    expect(v2).toBeGreaterThanOrEqual(wantImage)
    expect(v2).toBeGreaterThan(v1)
  })
})

describe('v1 text under-counts are known and NOT fixed by v2', () => {
  // Recorded rather than fixed: v2 only changes the image term. A reader seeing
  // a green suite should not conclude these are handled.
  const real = new Map(corpus.samples.map((s) => [s.name, s.real_tokens]))
  for (const name of [
    'adversarial_base64',
    'adversarial_hex',
    'adversarial_uuids',
    'emoji_dense',
    'json_in_content',
  ]) {
    it(name, () => {
      const want = real.get(name)
      expect(want, `corpus fixture is missing ${name}`).toBeDefined()
      const body = sampleBody(name)
      const v1 = inputTokenBound(body)
      expect(v1, 'v1 no longer under-counts; update this list').toBeLessThan(want!)
      expect(inputTokenBoundV2(body), 'v2 must not touch the text term').toBe(v1)
    })
  }
})

describe('bound version dispatch', () => {
  it('maps wire versions to implementations', () => {
    const body = sampleBody('image_png_512')
    const v1 = inputTokenBound(body)
    const v2 = inputTokenBoundV2(body)
    expect(v1).not.toBe(v2)

    expect(inputTokenBoundVersion(body, 0)).toBe(v1)
    expect(inputTokenBoundVersion(body, BOUND_VERSION_1)).toBe(v1)
    expect(inputTokenBoundVersion(body, BOUND_VERSION_2)).toBe(v2)
    expect(inputTokenBoundVersion(body, 99)).toBe(v1)
  })

  it('reports supported versions', () => {
    expect(supportedBoundVersion(0)).toBe(true)
    expect(supportedBoundVersion(1)).toBe(true)
    expect(supportedBoundVersion(2)).toBe(true)
    expect(supportedBoundVersion(3)).toBe(false)
  })
})

describe('adversarial inputs are bounded in time', () => {
  // The trailing-'=' strip was a catastrophic-backtracking regex: 2.8 SECONDS
  // per image part at the scan cap, on the browser main thread, reachable from
  // a node-returned image replayed on every later turn.
  it('an all-padding data URL is fast', () => {
    const body = JSON.stringify({
      model: 'm',
      messages: [
        {
          role: 'user',
          content: [
            { type: 'image_url', image_url: { url: 'data:image/png;base64,' + '='.repeat(87383) + 'A' } },
          ],
        },
      ],
    })
    const started = Date.now()
    inputTokenBoundV2(body)
    expect(Date.now() - started).toBeLessThan(250)
  })

  it('a deeply nested body does not throw', () => {
    const body = '{"a":' + '['.repeat(5000) + '"x"' + ']'.repeat(5000) + '}'
    expect(() => inputTokenBoundV2(body)).not.toThrow()
  })
})
