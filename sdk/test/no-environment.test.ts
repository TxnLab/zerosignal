/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The SDK reads no environment: every setting arrives through Config.
// import.meta.env is Vite's and breaks Node outright; process.env does not
// exist in a browser. The typecheck already refuses a bare import.meta.env
// (src builds with no ambient types), so this catches the spellings that get
// past it, such as a cast.

import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const src = fileURLToPath(new URL('../src', import.meta.url))

function sources(dir: string): string[] {
    return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
        e.isDirectory() ? sources(join(dir, e.name)) : e.name.endsWith('.ts') ? [join(dir, e.name)] : [],
    )
}

describe('the SDK reads no environment', () => {
    it('has sources to check', () => {
        expect(sources(src).length).toBeGreaterThan(0)
    })

    it.each(sources(src).map((p) => [p.slice(src.length + 1), p]))('%s', (_, path) => {
        const text = readFileSync(path, 'utf8')
        // import.meta.env, (import.meta as any).env, and the like.
        expect(text).not.toMatch(/\bimport\.meta\b[^\n;]*\.env\b/)
        expect(text).not.toMatch(/\bprocess\.env\b/)
    })
})
