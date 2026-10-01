/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Cross-impl parity test for inferDialect / hostMatchesDomain. Loads
// proto/testdata/dialect_vectors.json (produced by
// proto/go/inject/dialect_vectors_test.go, whose expectations are hand-authored).
//
// If this fails, a TEE verifier and a node can classify the same upstream URL
// differently — admitting a lookalike as xAI, or refusing a genuine node.

import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  inferDialect,
  hostMatchesDomain,
  httpsUpstreamHost,
  namedUpstreamAdmissible,
  upstreamAttested,
} from '../src/inject/index.js'

interface DialectCase {
  url: string
  want: string
  why?: string
}

interface HostCase {
  host: string
  domain: string
  want: boolean
}

interface HTTPSHostCase {
  url: string
  host: string
}

interface AdmissibleCase {
  name: string
  posture_json: string
  upstream_attested: boolean
  want: boolean
}

interface DialectVectorsFile {
  version: number
  infer_dialect: DialectCase[]
  host_matches_domain: HostCase[]
  https_upstream_host: HTTPSHostCase[]
  named_upstream_admissible: AdmissibleCase[]
  upstream_attested: { block_json: string; want: boolean; why?: string }[]
}

const here = path.dirname(fileURLToPath(import.meta.url))
const vectorsPath = path.resolve(here, '..', '..', 'testdata', 'dialect_vectors.json')
const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf8')) as DialectVectorsFile

describe('dialect vectors', () => {
  it('has cases', () => {
    expect(vectors.infer_dialect.length).toBeGreaterThan(40)
    expect(vectors.host_matches_domain.length).toBeGreaterThan(5)
  })

  for (const c of vectors.infer_dialect) {
    it(`inferDialect(${JSON.stringify(c.url)})`, () => {
      expect(inferDialect(c.url), c.why).toBe(c.want)
    })
  }

  for (const c of vectors.host_matches_domain) {
    it(`hostMatchesDomain(${JSON.stringify(c.host)}, ${JSON.stringify(c.domain)})`, () => {
      expect(hostMatchesDomain(c.host, c.domain)).toBe(c.want)
    })
  }

  for (const c of vectors.https_upstream_host) {
    it(`httpsUpstreamHost(${JSON.stringify(c.url)})`, () => {
      expect(httpsUpstreamHost(c.url)).toBe(c.host === '' ? null : c.host)
    })
  }

  it('has admissibility cases', () => {
    expect(vectors.named_upstream_admissible.length).toBeGreaterThan(5)
  })

  for (const c of vectors.named_upstream_admissible) {
    it(`namedUpstreamAdmissible: ${c.name}`, () => {
      const posture: unknown = c.posture_json === '' ? undefined : JSON.parse(c.posture_json)
      expect(namedUpstreamAdmissible(posture, c.upstream_attested)).toBe(c.want)
    })
  }

  it('has upstream_attested cases', () => {
    expect(vectors.upstream_attested.length).toBeGreaterThan(5)
  })

  for (const c of vectors.upstream_attested) {
    it(`upstreamAttested(${c.block_json || '<absent>'})`, () => {
      const block: unknown = c.block_json === '' ? undefined : JSON.parse(c.block_json)
      expect(upstreamAttested(block), c.why).toBe(c.want)
    })
  }
})
