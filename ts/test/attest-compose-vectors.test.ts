/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The TypeScript half of proto/testdata/compose_vectors.json. The Go half is
// proto/go/attest/compose_vectors_test.go, which GENERATES the file.
//
// Regenerate: cd proto/go && go test ./attest -run TestComposeVectors -update-compose
//             cd proto/ts && pnpm test
//
// WHY BOTH HALVES MUST EXIST. attest-compose.test.ts is a hand-written suite
// that asserts about this language only, and its Go counterpart does the same
// on its side. Under exactly that arrangement a review found a live
// divergence: every whitespace decision was `String.prototype.trim` here and
// `strings.TrimSpace` there, which are different predicates, and the two
// reached opposite verdicts on adversary-chosen bytes while BOTH suites stayed
// green. This file is the thing that could not have stayed green — the inputs
// and the expected answers are one file, produced by Go, consumed here.
//
// Two more real defects surfaced on the vectors' first run, which is the
// argument for them in one line: a `docker_compose_file` of a single U+0085
// verified CLEAN in both languages (agreeing, on the wrong answer — it
// sidestepped `empty_docker_compose`, the only rule guarding that field
// today), and `null` was `app_compose_malformed` here but a pile of policy
// violations in Go.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, it } from 'vitest'

import {
    ComposeError,
    ComposeSkeletonError,
    EVENT_COMPOSE_HASH,
    composeSkeletonDigest,
    extractComposeSkeleton,
    phalaPreLaunchDigests,
    rootBackdoorEnvs,
    verifyAppCompose,
    zeroSignalComposePolicy,
    zeroSignalSecretEnvNames,
} from '../src/attest/index.js'
import type { ComposePolicy } from '../src/attest/index.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const vectorsPath = path.resolve(here, '../../testdata/compose_vectors.json')

interface SkeletonVector {
    name: string
    why: string
    docker_compose: string
    error_code?: string
    skeleton_sha256?: string
    image_ref?: string
}

interface DocumentVector {
    name: string
    why: string
    app_compose: string
    policy: string
    sealed: boolean
    error_code?: string
    violations?: string[]
}

interface ComposeVectors {
    release_compose: string
    release_image: string
    release_config: string
    sidecar_compose: string
    sidecar_engine: string
    shared_policy: {
        manifest_version: number
        runner: string
        allowed_env_names: string[]
        allowed_env_suffixes: string[]
        enforce_env_allowlist: boolean
        pre_launch_script_digests: string[]
        enforce_compose_skeleton: boolean
        root_backdoor_envs: string[]
        allowed_root_backdoor_envs: string[]
        trusted_os_images: string[]
    }
    skeletons: SkeletonVector[]
    documents: DocumentVector[]
}

const V: ComposeVectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'))

function hexOf(s: string): string {
    return Array.from(sha256(new TextEncoder().encode(s)))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
}

/**
 * Resolves a policy NAME to the same object Go used.
 *
 * Deliberately built from this language's own `zeroSignalComposePolicy()`
 * rather than deserialized from the vector file. Deserializing would test the
 * deserializer: the point is that TS's own shared policy, the one the browser
 * client actually ships, produces Go's answers.
 */
function policyFor(name: string): ComposePolicy {
    const shared = zeroSignalComposePolicy()
    switch (name) {
        case 'empty':
            return {}
        case 'zerosignal':
            return shared
        case 'enforced': {
            const { skeleton, imageRef } = extractComposeSkeleton(V.release_compose)
            return {
                ...shared,
                enforceComposeSkeleton: true,
                trustedComposeSkeletons: [composeSkeletonDigest(skeleton)],
                trustedNodeImages: [imageRef],
            }
        }
        case 'sidecar_enforced': {
            // Built from `sidecar_compose`, never from the document under
            // test: rebuilding it per-document would derive the policy from
            // the very bytes it is meant to judge, and would accept the
            // engine swap it exists to catch.
            const { skeleton, imageRef } = extractComposeSkeleton(V.sidecar_compose)
            return {
                ...shared,
                enforceComposeSkeleton: true,
                trustedComposeSkeletons: [composeSkeletonDigest(skeleton)],
                trustedNodeImages: [imageRef],
            }
        }
        case 'closed':
            return { ...shared, enforceComposeSkeleton: true }
        case 'misconfigured': {
            const { skeleton, imageRef } = extractComposeSkeleton(V.release_compose)
            return {
                ...shared,
                trustedComposeSkeletons: [composeSkeletonDigest(skeleton)],
                trustedNodeImages: [imageRef],
            }
        }
        case 'storage':
            return { ...shared, storageFs: 'ext4' }
        default:
            throw new Error(`unknown policy ${name}`)
    }
}

describe('compose golden vectors — the shared policy', () => {
    // Pinned against GO's values, not against a hand-typed list. The previous
    // version of this assertion in attest-compose.test.ts typed the four env
    // names out here, so deleting one from the Go slice — a widening of the
    // unmeasured-env allowlist, the most load-bearing field in the module —
    // turned only this side red and told you nothing about which side moved.
    it('matches Go field for field', () => {
        const p = zeroSignalComposePolicy()
        expect(p.manifestVersion).toBe(V.shared_policy.manifest_version)
        expect(p.runner).toBe(V.shared_policy.runner)
        expect([...zeroSignalSecretEnvNames()].sort()).toEqual(
            [...V.shared_policy.allowed_env_names].sort(),
        )
        expect([...(p.allowedEnvSuffixes ?? [])].sort()).toEqual(
            [...V.shared_policy.allowed_env_suffixes].sort(),
        )
        expect(p.enforceEnvAllowlist).toBe(V.shared_policy.enforce_env_allowlist)
        expect([...phalaPreLaunchDigests()].sort()).toEqual(
            [...V.shared_policy.pre_launch_script_digests].sort(),
        )
        expect([...rootBackdoorEnvs()].sort()).toEqual(
            [...V.shared_policy.root_backdoor_envs].sort(),
        )
        // The per-release half ships off. When this flips, the trusted lists
        // must have been populated in the same change.
        expect(p.enforceComposeSkeleton ?? false).toBe(
            V.shared_policy.enforce_compose_skeleton,
        )
    })

    // Go grew ComposePolicy.AllowedRootBackdoorEnvs for ONE caller — appraising
    // a third-party attested upstream, which only the node does. This module
    // never appraises anything but a zs-node, so the field is deliberately
    // ABSENT here rather than present-and-ignored: an unused knob in the
    // browser bundle reads as a supported one.
    //
    // The vector is what makes that divergence safe. Without it the Go-side
    // test protects Go alone, and the browser ships its own copy of this
    // policy — so a concession added here would be caught by nothing.
    it('concedes no root-backdoor env, and has no way to', () => {
        expect(V.shared_policy.allowed_root_backdoor_envs).toEqual([])
        expect('allowedRootBackdoorEnvs' in zeroSignalComposePolicy()).toBe(false)
    })
})

describe('compose golden vectors — skeleton extraction', () => {
    it.each(V.skeletons.map((s) => [s.name, s] as const))('%s', (_name, s) => {
        if (s.error_code) {
            let code: string | undefined
            try {
                extractComposeSkeleton(s.docker_compose)
            } catch (e) {
                if (e instanceof ComposeSkeletonError) code = e.code
                else throw e
            }
            expect(code, s.why).toBe(s.error_code)
            return
        }
        const { skeleton, imageRef } = extractComposeSkeleton(s.docker_compose)
        // Both, always. A walk that returned empty strings would satisfy an
        // assertion on either one alone.
        expect(composeSkeletonDigest(skeleton), s.why).toBe(s.skeleton_sha256)
        expect(imageRef, s.why).toBe(s.image_ref)
    })
})

describe('compose golden vectors — document policy', () => {
    it.each(V.documents.map((d) => [d.name, d] as const))('%s', (_name, d) => {
        const measurements = { [EVENT_COMPOSE_HASH]: hexOf(d.app_compose) }
        const policy = policyFor(d.policy)

        let code: string | undefined
        let violations: string[] = []
        try {
            verifyAppCompose(d.app_compose, measurements, policy)
        } catch (e) {
            if (!(e instanceof ComposeError)) throw e
            code = e.code
            violations = e.violations.map((v) => v.code).sort()
        }

        expect(code, d.why).toBe(d.error_code)
        expect(violations, d.why).toEqual(d.violations ?? [])
    })
})

describe('compose golden vectors — the fixture set itself', () => {
    // A vector file regenerated into something one-sided pins nothing, and it
    // would look exactly like a passing suite. These are the same self-checks
    // the Go generator runs, asserted again on the consumed file so a
    // hand-edited or truncated copy is caught here too.
    it('exercises both directions', () => {
        expect(V.skeletons.filter((s) => s.error_code).length).toBeGreaterThan(0)
        expect(V.skeletons.filter((s) => !s.error_code).length).toBeGreaterThan(0)
        expect(V.documents.filter((d) => d.error_code).length).toBeGreaterThan(0)
        expect(V.documents.filter((d) => !d.error_code).length).toBeGreaterThan(0)
    })

    it('carries the release compose, so this file is not a second fixture', () => {
        // The whole reason release_compose travels in the vectors: it used to
        // be hand-duplicated here, with a comment claiming byte-identity with
        // Go's copy and nothing enforcing it.
        expect(V.release_compose).toContain(V.release_image)
        expect(V.release_compose).toContain('NODE_CONFIG_YAML: |')
        const { imageRef } = extractComposeSkeleton(V.release_compose)
        expect(imageRef).toBe(V.release_image)
    })

    it('carries a sidecar compose whose SECOND image is the one preserved', () => {
        // Pins that `sidecar_compose` is actually the two-service shape and
        // that the lifting rule points the way the sidecar policy assumes.
        // Without this the field could degrade into a copy of the release
        // compose and every sidecar document vector would still pass.
        expect(V.sidecar_compose).toContain(V.release_image)
        expect(V.sidecar_compose).toContain(V.sidecar_engine)
        expect(V.sidecar_engine).not.toBe(V.release_image)

        const { skeleton, imageRef } = extractComposeSkeleton(V.sidecar_compose)
        expect(imageRef).toBe(V.release_image)
        expect(skeleton).toContain(V.sidecar_engine)
        expect(skeleton).not.toContain(V.release_image)
    })
})
