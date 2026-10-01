/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// TypeScript mirror of proto/go/attest/compose.go — validating the
// CONTENT of the app-compose document dstack hashed into RTMR3.
//
// dstack hashes a JSON document — its `app-compose.json` — into RTMR3
// as the `compose-hash` runtime event. Allowlisting that hash does not
// scale: every operator and every redeploy produces a distinct one, so
// a relying party would need a curated entry per deployment. Worse, a
// hash allowlist is only ever as good as a human having read the
// document behind it, and a compose can measure nothing at all — our
// own probe compose pins `image: ${PROBE_IMAGE}`, which is a stable
// hash over arbitrary code.
//
// So this validates the content instead. The preimage is recoverable in
// band: `sha256(tcb_info.app_compose) === compose_hash` exactly,
// measured on a live Phala tdx.small CVM 2026-08-28, and the full
// document already rides the guest agent's /Info response. Check the
// hash against the REPLAYED event log first, then read fields off a
// document that is now known to be the one the hardware measured.
//
// Both a Go proxy and a browser client run this, for the same reason
// the replay itself is shared: two implementations of a security gate
// disagree silently, and every wrong answer here is well-formed.

import { sha256 } from '@noble/hashes/sha2.js'

import { EVENT_COMPOSE_HASH } from './dstack.js'

/**
 * Why an app-compose document could not be verified.
 *
 * Each names a branch that fails OPEN under a plausible edit: returning
 * the parsed document without throwing hands a verifier fields it never
 * checked the provenance of.
 */
export type ComposeErrorCode =
    /**
     * The replayed event log carried no compose-hash event, so there is
     * nothing to check the document against.
     *
     * Distinct from a mismatch on purpose. Treating "absent" as "skip"
     * is the whole vulnerability: a node that simply omits the event
     * would validate against nothing while every field rule below still
     * reports clean.
     */
    | 'no_compose_hash'
    /**
     * The bundle published no app-compose document. An empty preimage
     * still hashes to a well-formed digest, so this must fail before
     * the comparison rather than hash '' and report a mismatch — the
     * two are different findings and only one is the operator's fault.
     */
    | 'no_app_compose'
    /** The published document is not the one the hardware measured. */
    | 'compose_hash_mismatch'
    /** The document did not parse as an app-compose shape at all. */
    | 'app_compose_malformed'
    /** The document verified but violates the content policy. */
    | 'compose_policy'

export class ComposeError extends Error {
    readonly code: ComposeErrorCode
    /** Populated only for `compose_policy`. */
    readonly violations: readonly Violation[]
    /**
     * The parsed document, on `compose_policy` only — it is the one code
     * raised AFTER parsing succeeded.
     *
     * Mirrors Go, where `VerifyAppCompose` returns `(doc, *ComposePolicyError)`
     * together and `TestPolicyError_StillReturnsTheDocument` pins it. The
     * reason is the same on both sides and it is a security one, not a
     * convenience: a caller that wants to report WHAT it refused would
     * otherwise have to re-parse the untrusted document to build that message,
     * which re-opens the gate this module closed. Handing back the copy that
     * already passed the hash check is what removes the temptation.
     */
    readonly doc?: AppCompose

    constructor(
        code: ComposeErrorCode,
        message: string,
        violations: readonly Violation[] = [],
        doc?: AppCompose,
    ) {
        super(message)
        this.name = 'ComposeError'
        this.code = code
        this.violations = violations
        this.doc = doc
    }
}

/**
 * dstack's app-compose.json, the document hashed into RTMR3.
 *
 * Field set captured from a live Phala tdx.small CVM (dstack-0.5.9,
 * manifest_version 2). Unknown fields are a POLICY VIOLATION rather
 * than something to ignore — see `unknown_field`.
 */
export interface AppCompose {
    manifest_version: number
    name: string
    runner: string
    docker_compose_file: string
    pre_launch_script: string
    allowed_envs: string[]
    features: string[]

    gateway_enabled: boolean
    tproxy_enabled: boolean
    kms_enabled: boolean
    local_key_provider_enabled: boolean
    no_instance_id: boolean
    secure_time: boolean
    public_logs: boolean
    public_sysinfo: boolean
    public_tcbinfo: boolean

    storage_fs: string
}

/**
 * The exact top-level key set this module models.
 *
 * It exists because "I validated the fields I know about" is not "I
 * validated the document". A dstack release that adds a top-level key —
 * another boot hook, another key-delivery channel — would otherwise
 * ride through every check below reporting clean, and the failure would
 * be invisible in both logs.
 */
const KNOWN_APP_COMPOSE_FIELDS: readonly string[] = [
    'allowed_envs',
    'docker_compose_file',
    'features',
    'gateway_enabled',
    'kms_enabled',
    'local_key_provider_enabled',
    'manifest_version',
    'name',
    'no_instance_id',
    'pre_launch_script',
    'public_logs',
    'public_sysinfo',
    'public_tcbinfo',
    'runner',
    'secure_time',
    'storage_fs',
    'tproxy_enabled',
]

/**
 * A class of policy failure. Stable strings, because both a Go proxy
 * and a browser client surface them and a renumbering would silently
 * change what a UI says.
 */
export type ViolationCode =
    | 'unknown_field'
    | 'manifest_version'
    | 'runner'
    | 'root_backdoor_env'
    | 'env_not_allowed'
    | 'pre_launch_script'
    | 'toggle'
    | 'empty_docker_compose'
    | 'compose_skeleton'
    | 'node_image'
    | 'feature'
    | 'storage_fs'
    // Refuses an engine-config span declaring a setting able to change what
    // the model SAYS rather than how fast it says it. Checked on the payer's
    // side because a node-side check protects an honest operator from a
    // mistake and protects a payer from nothing.
    | 'engine_config_key'
    // About the VERIFIER, not the node: reference data present, the flag
    // that consults it absent. Every other code says the operator did
    // something.
    | 'policy_misconfigured'

/** One policy failure, named specifically enough to act on. */
export interface Violation {
    code: ViolationCode
    detail: string
}

/**
 * The env names that hand the operator a root shell in a CVM whose
 * attestation says nobody has one.
 *
 * Checked regardless of `allowedEnvNames` and reported under their own
 * code, because "unknown env name" and "the operator installed a root
 * key" are not findings of the same severity.
 *
 * DSTACK_AUTHORIZED_KEYS is not hypothetical: `phala deploy` appends it
 * silently, from the first of ~/.ssh/{id_rsa,id_ed25519,id_ecdsa,
 * id_dsa}.pub that exists, unless --no-dev-os is passed. No prompt, no
 * output. The only visible trace is this name appearing in
 * allowed_envs, which is how it was found in the first place.
 */
export function rootBackdoorEnvs(): readonly string[] {
    return ['DSTACK_AUTHORIZED_KEYS', 'DSTACK_ROOT_PUBLIC_KEY', 'DSTACK_ROOT_PASSWORD']
}

/**
 * The pre-launch scripts a ZeroSignal verifier recognizes: the script measured
 * on the 2026-08-25 tdx.small capture (17059 bytes, self-identifying as
 * v0.0.19) and the one measured on the 2026-09-02 GPU capture (17569 bytes,
 * v0.0.20).
 *
 * THE PREDICTION BELOW CAME TRUE IN EIGHT DAYS, which is the useful thing to
 * know about this list's cadence. Nothing announced v0.0.20; it arrived under a
 * CVM we deployed, and the only reason it did not de-route that node is that
 * nobody was routing to it yet.
 *
 * AN EARLIER VERSION OF THIS COMMENT SAID THESE ARE "shipped by known phala
 * CLI releases". That is false, and the correction matters because it changes
 * who controls the value. The script is NOT in the CLI — `grep -rl
 * 'home/root/.ssh' package/` over phala@1.1.21 finds nothing. The Phala Cloud
 * API injects it server-side at deploy time, so its digest moves on Phala's
 * schedule, with no version to track and nothing an npm sweep could enumerate.
 * Verified 2026-08-29.
 *
 * The rule is unconditional — it fires today, on any node publishing a
 * preimage, regardless of `enforceComposeSkeleton` — so the first time Phala
 * edits their template, newly deployed nodes are refused while behaving
 * perfectly. The browser has no config file, so unlike the proxy it has no
 * override: this list moving is a client redeploy. That is the same cost
 * `tee-allowlist.ts` reasons about for OS images, and the reason a
 * transparency log is the designed end state.
 *
 * Widening this by guessing is not an option — a digest admitted here blesses
 * 17KB of root-privileged bash sight unseen.
 *
 * v0.0.20 was read in full and diffed against v0.0.19 before being added, and
 * it grants NOTHING new. The delta is a hardening pass for being sourced under
 * `set -u`: most hunks wrap a bare "$VAR" as "${VAR-}", one initializes the
 * locals in the fingerprint helper for the same reason, two reflow a
 * multi-line pipeline onto one line, one rewrites `tr -d '"'"'"` as two `tr`
 * calls over the same two-character set, and one bumps the version echo.
 *
 * THREE hunks change behavior, and all three narrow rather than widen:
 * DOCKER_REGISTRY_TARGET moves out of the docker-credentials branch (the GHCR
 * block below referenced it unbound otherwise), the app-compose.json read
 * gains an `[[ -f … ]]` guard, and the DSTACK_APP_DOMAIN export now also
 * requires a non-empty DSTACK_APP_ID. The count is spelled out because an
 * enumeration is what spares the next reader from re-deriving 17KB of bash,
 * and an enumeration that is merely nearly complete is worse than none.
 *
 * Every root-privileged operation is byte-identical: the same root-password
 * paths, and the same three SSH-key channels — DSTACK_ROOT_PUBLIC_KEY,
 * DSTACK_AUTHORIZED_KEYS, and `ssh_authorized_keys` in the host-provisioned
 * /dstack/user_config. The first two are why `rootBackdoorEnvs` exists; the
 * third is reachable via `phala deploy --ssh-pubkey`, rides no measured field,
 * and is therefore something this policy cannot see.
 */
export function phalaPreLaunchDigests(): readonly string[] {
    return [
        'cec8f68ce6185b912023d886bba20cd06386dd9751af904e6107e758b9d68983',
        '982181610f70be9087b1c69b36b719b47b82d37fcef8acc9289ed3bb3095ffe8',
    ]
}

/**
 * The exact environment variable names a ZeroSignal node deployment may declare
 * in the unmeasured channel, alongside the `*_MNEMONIC` suffix (see
 * `zeroSignalComposePolicy`).
 *
 * EVERY ONE OF THESE CARRIES A CREDENTIAL AND NOTHING ELSE. That is the
 * membership rule, and the reason the list is short in a namespace that is not:
 * the node's applyEnv reads ~119 distinct `NODE_*` names and all but these are
 * configuration. Since applyEnv runs AFTER the measured `NODE_CONFIG_YAML` is
 * unmarshalled, a name outside this list is an unmeasured override of the
 * measured document — `NODE_LLM_OPENAI_BASE_URL` redirects the one upstream the
 * rung-1 claim names, `NODE_TEE_DATAFLOW` rewrites the claim itself. Neither
 * moves compose_hash once the name is declared, because dstack measures the
 * name and not the value.
 *
 * So this list is what makes "the configuration is inside the measurement" true
 * rather than nearly true. Adding a name is a decision about what an operator
 * may change after attestation, not a convenience.
 */
export function zeroSignalSecretEnvNames(): readonly string[] {
    return [
        'NODE_LLM_OPENAI_API_KEY',
        'NODE_IMAGE_LLM_OPENAI_API_KEY',
        'NODE_LLM_COMFYUI_CLOUD_API_KEY',
        // Cloud secret references, not secrets — the URLs name a secret
        // manager. Still a credential channel, still no configuration
        // reachable through it.
        'ZS_MNEMONIC_URLS',
        // The algod bearer token. Read by applyEnv like every other NODE_*
        // name, but it is a CREDENTIAL and the value reaches nothing
        // configurable — which is the membership rule above, and it was
        // simply missed. Its absence had a cost: an operator on a
        // token-authenticated algod had to inline the token into
        // NODE_CONFIG_YAML, which since 9.6 the node serves unauthenticated
        // to anyone who asks, or be refused outright. "Publish your token or
        // don't run" is not a choice a policy should force.
        'NODE_ALGOD_TOKEN',
    ]
}

/**
 * The content policy a ZeroSignal relying party enforces on a dstack node's
 * measured compose.
 *
 * It lives here rather than being spelled out in the browser client and again in
 * the proxy, because the two would then assert the same rules in two places and
 * execute them in none. The per-RELEASE data (which zs-node image digests are
 * published) is deliberately NOT here: that list moves on each consumer's own
 * cadence, exactly like the trusted OS-image list.
 *
 * WHAT A CLEAN RESULT FROM *THIS POLICY ALONE* DOES NOT ESTABLISH, because the
 * distinction is easy to lose: the module implements the template match over
 * `docker_compose_file` (`extractComposeSkeleton` + `trustedComposeSkeletons` +
 * `trustedNodeImages`), but the per-RELEASE half of it is not here. This policy
 * leaves `enforceComposeSkeleton` unset and both lists empty, so on its own the
 * workload is unchecked — a compose pinning `image: ${SOME_VAR}` holds a stable
 * compose_hash over arbitrary code and passes every rule enabled here.
 *
 * THAT IS A PROPERTY OF THIS FUNCTION, NOT OF THE FLEET. Both shipped consumers
 * supply the release lists and set the flag: zs-proxy from its config defaults,
 * and this repo's browser client from `tee-allowlist.ts`. The lists live there
 * rather than here because they move on each consumer's own release cadence,
 * exactly like the trusted OS-image list — so a library caller that takes this
 * policy verbatim gets the weaker check, and needs to say so rather than
 * inherit the fleet's reputation for it.
 *
 * A consumer supplying the lists sets the flag in the same change. Setting one
 * without the other is a defect the policy check reports
 * (`policy_misconfigured`), because a populated list with the flag off consults
 * nothing while looking configured.
 */
export function zeroSignalComposePolicy(): ComposePolicy {
    return {
        manifestVersion: 2,
        runner: 'docker-compose',

        allowedEnvNames: zeroSignalSecretEnvNames(),
        allowedEnvSuffixes: ['_MNEMONIC'],
        // Explicit, because an empty allowedEnvNames must never be readable
        // as "no constraint" — see the field's doc comment.
        enforceEnvAllowlist: true,

        preLaunchScriptDigests: phalaPreLaunchDigests(),

        // Observed on the 2026-08 tdx.small capture. `kms` is the key
        // provider, `tproxy-net` the gateway — both are the platform's own
        // switches, not the operator's, which is why enumerating them is
        // tractable at all. A dstack release adding a feature refuses nodes
        // using it until this moves; that is the stated cost of checking the
        // field rather than ignoring it, and ignoring it is what let it ride
        // through unread.
        allowedFeatures: ['kms', 'tproxy-net'],

        toggles: {
            // The one toggle pinned on evidence rather than preference.
            // local_key_provider_enabled means the CVM derives its own keys
            // instead of taking them from Phala's KMS; the deployment this
            // policy describes uses the KMS path, and a node flipping it is a
            // different key-custody story than the one attested.
            local_key_provider_enabled: false,
        },
    }
}

/** Pins app-compose's boolean switches. `undefined` means "not checked". */
export interface ComposeToggles {
    gateway_enabled?: boolean
    tproxy_enabled?: boolean
    kms_enabled?: boolean
    local_key_provider_enabled?: boolean
    no_instance_id?: boolean
    secure_time?: boolean
    public_logs?: boolean
    public_sysinfo?: boolean
    public_tcbinfo?: boolean
}

/**
 * The set of content rules a relying party enforces.
 *
 * Every field is data rather than a hardcoded constant so the proxy and
 * the browser client run the SAME implementation over a list each can
 * update on its own release cadence.
 */
export interface ComposePolicy {
    /** The version the document must declare. 0 or absent disables the check. */
    manifestVersion?: number
    /** The runner it must declare, e.g. 'docker-compose'. Empty disables the check. */
    runner?: string
    /**
     * The environment variable NAMES the compose may declare, matched
     * case-insensitively.
     *
     * dstack injects only names listed in the document's allowed_envs,
     * so this set is what stops the unmeasured env channel being a
     * general config-override path. Measured 2026-08-28: adding a NAME
     * moves compose_hash, changing a VALUE does not — exactly the split
     * that makes this rule enforceable remotely while a secret still
     * rotates without re-attesting.
     */
    allowedEnvNames?: readonly string[]
    /**
     * Permits a name by its SUFFIX, matched case-insensitively, for the one
     * secret channel whose names a policy cannot enumerate: the keystore
     * loads every `<ANYTHING>_MNEMONIC` in the environment, so the prefix is
     * operator-chosen by design.
     *
     * Deliberately narrow, and the reason a suffix is safe here when a prefix
     * rule would not be: a name grants power only through what reads it. The
     * node's applyEnv reads ~119 distinct `NODE_*` names, so `NODE_*` is a
     * config-override surface. `*_MNEMONIC` is read only by the keystore,
     * which treats the value as key material and the name as a label — there
     * is no setting reachable through it.
     *
     * A suffix that is empty or does not begin with `_` is IGNORED rather
     * than matched: `''` would permit every name and a bare-word suffix would
     * match any name merely ending in those letters. Both are fail-open.
     */
    allowedEnvSuffixes?: readonly string[]
    /**
     * Selects between the two readings of an absent/empty
     * `allowedEnvNames`. It exists so "allow everything" can only ever
     * be reached by writing it down: an empty list read as "no
     * constraint" is the fail-open shape this module exists to avoid.
     */
    enforceEnvAllowlist?: boolean
    /**
     * The sha256 digests (lowercase hex) the pre-launch script may have.
     *
     * Phala's own script is ~17 KB of bash that runs as root before the
     * container, and it is what writes DSTACK_AUTHORIZED_KEYS to root's
     * authorized_keys. It is measured, but measured only means "you can
     * tell which one" — pinning is what makes that useful. An EMPTY
     * script is always accepted.
     *
     * AN EMPTY LIST THEREFORE PERMITS ONLY AN EMPTY SCRIPT — it is the
     * strictest setting, not the absent one. That is the opposite of
     * how a list usually reads, which is why it has no
     * `enforcePreLaunch` twin: there is no way to spell "any boot hook
     * is fine", because there is no legitimate reason to want it.
     * Compare `allowedEnvNames`, where an unconstrained setting IS
     * legitimate during a migration and so had to be spellable.
     */
    preLaunchScriptDigests?: readonly string[]
    /**
     * The sha256 digests (lowercase hex) of published release compose
     * SKELETONS — see `extractComposeSkeleton`.
     *
     * This is the rule that makes content validation mean anything. Without it
     * a compose pinning `image: ${SOME_VAR}` holds a perfectly stable
     * compose_hash over arbitrary code and satisfies every other field here.
     */
    trustedComposeSkeletons?: readonly string[]
    /**
     * The published zs-node image references the compose may run, compared
     * verbatim (`ghcr.io/…@sha256:…`).
     *
     * It judges the FIRST `image:` in the document and no other. On a
     * single-service compose that is the only one; on the sealed_local sidecar
     * shape the later images are pinned by the skeleton instead, and are
     * required to be digest-pinned so that pin means something.
     *
     * So "the node's image" is a release-authoring convention the extractor
     * cannot know. A document that puts another service first hands this check
     * that service's reference, which is not on this list, so it is refused —
     * which makes the convention self-enforcing FOR A GIVEN release, but not
     * across releases. Publish a multi-image release that lists an engine
     * first and that engine's reference has to go on this list; from then on
     * it would satisfy some other release's node-image hole, which is the
     * released-engine-passes-as-released-node confusion the lifting rule
     * avoids. Keep the node's `image:` first in every published skeleton.
     *
     * Verbatim and not digest-only on purpose: a digest alone would accept the
     * right bytes served from any registry path, and the repository half is
     * what says these bytes are the ones CI published.
     */
    trustedNodeImages?: readonly string[]
    /**
     * Selects between the two readings of empty `trustedComposeSkeletons` /
     * `trustedNodeImages`, exactly as `enforceEnvAllowlist` does and for the
     * same reason: these are per-RELEASE data each consumer ships on its own
     * cadence, so an empty list read as "no constraint" would silently disable
     * the check on any build whose list had not been populated yet.
     *
     * With it set, an empty list refuses everything. That is the correct
     * fail-closed direction and matches the trusted OS-image list: a verifier
     * with no reference does not verify, it does not wave things through.
     *
     * The flag closes the empty-list reading and opens a NEW one, which is why
     * `checkPolicy` reports `policy_misconfigured` when the lists are
     * populated and this is false: that state performs no check and is
     * indistinguishable from a correct build, so a verifier shipping the data
     * and forgetting the switch looks exactly like one that meant to leave it
     * off. A misconfigured verifier is a finding, not a skip.
     */
    enforceComposeSkeleton?: boolean
    /**
     * The `features` set the document may declare.
     *
     * EMPTY MEANS UNCHECKED here, unlike `preLaunchScriptDigests`, and the
     * asymmetry is deliberate. An empty pre-launch list permits only an empty
     * script because there is no legitimate reason to want an arbitrary root
     * boot hook. dstack declares features on every real deployment — the
     * 2026-08 capture carries `kms` and `tproxy-net` — so "empty means only
     * empty" would refuse every honest node, and a rule that cannot ship is
     * worth less than one that can be switched off.
     */
    allowedFeatures?: readonly string[]
    /**
     * Pins the encrypted-filesystem backend. Empty means unchecked, because
     * the correct value is genuinely unsettled across dstack releases — the
     * field exists so the choice is visible rather than silently unmade.
     */
    storageFs?: string
    /**
     * Pins the boolean switches. An absent entry reports nothing, so a
     * switch whose correct value is genuinely unsettled stays visibly
     * unpinned rather than pinned to a guess.
     */
    toggles?: ComposeToggles
}

/**
 * Checks that a published app-compose document hashes to the value the
 * event-log replay recovered.
 *
 * Exported separately because it is the ONLY step that establishes
 * provenance, and a caller may legitimately want it without any content
 * policy. Everything in ComposePolicy is a statement about a document;
 * this is the step that makes it a statement about THIS CVM.
 *
 * `measurements` must come from `verifyEventLog` — that is, from a
 * replay already checked against the quote. Passing a self-reported map
 * turns this whole module into an elaborate way of comparing a document
 * to itself.
 *
 * `raw` must be the app_compose string EXACTLY as received.
 * Re-serializing it first would reorder keys and change whitespace, and
 * the digest would then be over a document dstack never saw.
 */
export function verifyComposeHash(
    raw: string,
    measurements: Readonly<Record<string, string>>,
): void {
    const want = normalizeHex(measurements[EVENT_COMPOSE_HASH] ?? '')
    if (!want) {
        throw new ComposeError('no_compose_hash', 'attest: event log carried no compose-hash')
    }
    if (!raw) {
        throw new ComposeError('no_app_compose', 'attest: bundle carried no app_compose')
    }
    const got = bytesToHex(sha256(new TextEncoder().encode(raw)))
    if (got !== want) {
        throw new ComposeError(
            'compose_hash_mismatch',
            `attest: app_compose does not hash to the measured compose-hash ` +
                `(document hashes to ${got}, log measured ${want})`,
        )
    }
}

/**
 * Checks a published app-compose document against the measurement that
 * was actually replayed out of the event log, then against the content
 * policy. Returns the parsed document, or throws a ComposeError.
 *
 * ORDER IS THE SAFETY PROPERTY. The hash gate runs first and throws
 * before a single field is read, so every rule below it is a statement
 * about the document the hardware measured rather than about a document
 * the node chose to send.
 *
 * Policy violations arrive THROUGH the thrown error rather than as a
 * second return value, mirroring Go. A `{ doc, violations }` shape
 * fails open under the most natural caller there is — one that checks
 * for a thrown error and reads `doc` otherwise — which accepts a
 * document with a full list of findings. There is no way to write that
 * bug against this shape.
 */
export function verifyAppCompose(
    raw: string,
    measurements: Readonly<Record<string, string>>,
    policy: ComposePolicy = {},
): AppCompose {
    verifyComposeHash(raw, measurements)

    const { doc, unknown } = parseAppCompose(raw)
    const violations = checkPolicy(doc, unknown, policy)
    if (violations.length > 0) {
        const parts = violations.map((v) => `${v.code}: ${v.detail}`).join('; ')
        throw new ComposeError(
            'compose_policy',
            `attest: app_compose violates policy [${parts}]`,
            violations,
            doc,
        )
    }
    return doc
}

function parseAppCompose(raw: string): { doc: AppCompose; unknown: string[] } {
    let parsed: unknown
    try {
        parsed = JSON.parse(raw)
    } catch (e) {
        throw new ComposeError(
            'app_compose_malformed',
            `attest: app_compose is not a well-formed app-compose document: ${String(e)}`,
        )
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw new ComposeError(
            'app_compose_malformed',
            'attest: app_compose is not a JSON object',
        )
    }
    const obj = parsed as Record<string, unknown>
    const unknown = Object.keys(obj)
        .filter((k) => !KNOWN_APP_COMPOSE_FIELDS.includes(k))
        .sort()

    // Absent fields take Go's zero value, so the two implementations
    // agree on a document that simply omits one.
    const doc: AppCompose = {
        manifest_version: num(obj.manifest_version),
        name: str(obj.name),
        runner: str(obj.runner),
        docker_compose_file: str(obj.docker_compose_file),
        pre_launch_script: str(obj.pre_launch_script),
        allowed_envs: strArray(obj.allowed_envs),
        features: strArray(obj.features),
        gateway_enabled: bool(obj.gateway_enabled),
        tproxy_enabled: bool(obj.tproxy_enabled),
        kms_enabled: bool(obj.kms_enabled),
        local_key_provider_enabled: bool(obj.local_key_provider_enabled),
        no_instance_id: bool(obj.no_instance_id),
        secure_time: bool(obj.secure_time),
        public_logs: bool(obj.public_logs),
        public_sysinfo: bool(obj.public_sysinfo),
        public_tcbinfo: bool(obj.public_tcbinfo),
        storage_fs: str(obj.storage_fs),
    }
    return { doc, unknown }
}

function checkPolicy(
    c: AppCompose,
    unknown: readonly string[],
    p: ComposePolicy,
): Violation[] {
    const v: Violation[] = []
    const add = (code: ViolationCode, detail: string) => v.push({ code, detail })

    for (const k of unknown) {
        add(
            'unknown_field',
            `this dstack release carries a top-level field "${k}" that no rule here covers`,
        )
    }
    if (p.manifestVersion && c.manifest_version !== p.manifestVersion) {
        add('manifest_version', `want ${p.manifestVersion}, got ${c.manifest_version}`)
    }
    if (p.runner && c.runner !== p.runner) {
        add('runner', `want "${p.runner}", got "${c.runner}"`)
    }

    // A document with no compose measures nothing while producing a
    // perfectly well-formed hash — the vacuous-measurement shape.
    // The verifier's own configuration, checked before the node's document,
    // because a policy carrying reference data it never consults is not a
    // lenient policy — it is a broken one, and it looks identical to a
    // deliberate rollout state.
    if (
        !p.enforceComposeSkeleton &&
        ((p.trustedComposeSkeletons?.length ?? 0) > 0 || (p.trustedNodeImages?.length ?? 0) > 0)
    ) {
        add(
            'policy_misconfigured',
            `this policy carries ${p.trustedComposeSkeletons?.length ?? 0} trusted skeleton(s) ` +
                `and ${p.trustedNodeImages?.length ?? 0} trusted image(s) but ` +
                `enforceComposeSkeleton is false, so neither list is consulted`,
        )
    }

    // Deliberately NOT gated on enforceComposeSkeleton. That flag chooses
    // whether the document is matched against a published release; this is a
    // statement about the document's own content, and it must hold for a node
    // pinned by whole-document hash just as much as for a released one.
    for (const key of engineConfigViolations(c.docker_compose_file)) {
        add(
            'engine_config_key',
            `the engine config declares "${key}", which changes what the model produces ` +
                `rather than how fast it produces it — the weights digest cannot see it`,
        )
    }

    if (isBlank(c.docker_compose_file)) {
        add('empty_docker_compose', 'the measured document declares no compose at all')
    } else if (p.enforceComposeSkeleton) {
        let extracted: ComposeSkeleton | null = null
        try {
            extracted = extractComposeSkeleton(c.docker_compose_file)
        } catch (e) {
            // A document that cannot be taken apart is a document no
            // skeleton describes, so this is a violation and never a skip —
            // the shape that would let an operator disable the check by
            // writing a compose we cannot read.
            const why = e instanceof ComposeSkeletonError ? e.message : String(e)
            add('compose_skeleton', `cannot be read as a release compose: ${why}`)
        }
        if (extracted) {
            const digest = composeSkeletonDigest(extracted.skeleton)
            if (!containsFold(p.trustedComposeSkeletons ?? [], digest)) {
                add(
                    'compose_skeleton',
                    `does not match any published release compose (skeleton sha256 ${digest})`,
                )
            }
            // Checked separately from the skeleton because it moves on a
            // different cadence: the skeleton changes when the deployment's
            // SHAPE changes, the image on every release.
            if (!containsExact(p.trustedNodeImages ?? [], extracted.imageRef)) {
                add(
                    'node_image',
                    `runs ${extracted.imageRef}, which is not a published zs-node release`,
                )
            }
        }
    }

    const backdoor = new Set(rootBackdoorEnvs().map((n) => n.toUpperCase()))
    const allowed = new Set((p.allowedEnvNames ?? []).map((n) => trimAscii(n).toUpperCase()))
    for (const name of c.allowed_envs) {
        const up = trimAscii(name).toUpperCase()
        if (backdoor.has(up)) {
            add(
                'root_backdoor_env',
                `${name} installs an operator-held root credential inside the CVM`,
            )
        } else if (p.enforceEnvAllowlist && !allowed.has(up) && !hasAllowedSuffix(p, up)) {
            add(
                'env_not_allowed',
                `${name} is not a name this policy permits in the unmeasured env channel`,
            )
        }
    }

    if (c.pre_launch_script !== '') {
        const got = bytesToHex(sha256(new TextEncoder().encode(c.pre_launch_script)))
        if (!containsFold(p.preLaunchScriptDigests ?? [], got)) {
            add(
                'pre_launch_script',
                `runs an unrecognized root boot hook (${c.pre_launch_script.length} bytes, sha256 ${got})`,
            )
        }
    }

    // features and storage_fs were modelled and never read, which is the worst
    // of both: listing them in KNOWN_APP_COMPOSE_FIELDS suppressed the
    // unknown_field report that would have surfaced them, so a dstack feature
    // switch or a different encrypted-FS backend rode through reporting clean.
    // They are values, not merely names.
    if ((p.allowedFeatures?.length ?? 0) > 0) {
        for (const f of c.features) {
            if (!containsFold(p.allowedFeatures ?? [], trimAscii(f))) {
                add('feature', `declares the dstack feature "${f}", which this policy does not permit`)
            }
        }
    }
    if (p.storageFs && trimAscii(c.storage_fs).toLowerCase() !== p.storageFs.toLowerCase()) {
        add('storage_fs', `uses the "${c.storage_fs}" storage backend, want "${p.storageFs}"`)
    }

    const t = p.toggles ?? {}
    const pins: [keyof ComposeToggles, boolean | undefined, boolean][] = [
        ['gateway_enabled', t.gateway_enabled, c.gateway_enabled],
        ['tproxy_enabled', t.tproxy_enabled, c.tproxy_enabled],
        ['kms_enabled', t.kms_enabled, c.kms_enabled],
        ['local_key_provider_enabled', t.local_key_provider_enabled, c.local_key_provider_enabled],
        ['no_instance_id', t.no_instance_id, c.no_instance_id],
        ['secure_time', t.secure_time, c.secure_time],
        ['public_logs', t.public_logs, c.public_logs],
        ['public_sysinfo', t.public_sysinfo, c.public_sysinfo],
        ['public_tcbinfo', t.public_tcbinfo, c.public_tcbinfo],
    ]
    for (const [nameKey, want, got] of pins) {
        if (want !== undefined && want !== got) {
            add('toggle', `${String(nameKey)}: want ${want}, got ${got}`)
        }
    }
    return v
}

// The byte length of the pre-launch script matters for the message
// only; Go reports len() over bytes and JS over UTF-16 code units, and
// the scripts are ASCII. Nothing compares it.

/**
 * Placeholders substituted for the two operator-varying spans. They are the
 * only text a skeleton contains that the operator's document does not.
 */
const SKELETON_IMAGE_PLACEHOLDER = '<ZS-IMAGE>'
const SKELETON_CONFIG_PLACEHOLDER = '<ZS-CONFIG>'
const SKELETON_ENGINE_CONFIG_PLACEHOLDER = '<ZS-ENGINE-CONFIG>'

/**
 * The env name whose block scalar carries the node's measured configuration —
 * the one span an operator is expected to author.
 */
const COMPOSE_CONFIG_KEY = 'NODE_CONFIG_YAML'

/**
 * Names the compose top-level `configs:` entry whose `content:` block scalar
 * carries the inference engine's own configuration.
 *
 * WHY A SENTINEL NAME AND NOT A BARE `content:`. The compose spec fixes the key
 * as `content`, which is far too generic to lift on sight — any future config
 * entry would have its body silently excluded from the measurement, and the
 * whole safety of this walk is that a span nobody checks can never contain
 * compose directives. So the lift requires the EXACT two-line shape
 *
 *     <indent><COMPOSE_ENGINE_CONFIG_KEY>:
 *     <deeper>content: |
 *
 * and the sentinel line itself stays in the skeleton as structure. A `content:`
 * anywhere else is ordinary text and is hashed like any other line, which is the
 * safe direction: it can only make a document stop matching.
 */
// Exported for the same reason Go exports ComposeEngineConfigKey: `client/`
// builds operator-facing messages naming the block to edit, and a second
// hand-written copy of that string is one rename away from pointing at a key
// that no longer exists.
export const COMPOSE_ENGINE_CONFIG_KEY = 'zs-engine-config'

/** Why a compose could not be reduced to a skeleton. Each is a refusal. */
export type SkeletonErrorCode = 'tab_indent' | 'no_image' | 'unpinned_sidecar'

/** Thrown by `extractComposeSkeleton`. */
export class ComposeSkeletonError extends Error {
    readonly code: SkeletonErrorCode
    constructor(code: SkeletonErrorCode, message: string) {
        super(message)
        this.name = 'ComposeSkeletonError'
        this.code = code
    }
}

/** What `extractComposeSkeleton` recovers. */
export interface ComposeSkeleton {
    /** The structure, with every varying span replaced by a fixed placeholder. */
    skeleton: string
    /** The image reference lifted out, checked against its own release list. */
    imageRef: string
    /**
     * The engine-config bodies lifted out, in document order.
     *
     * RETURNED RATHER THAN RE-FOUND, and that is a security property. The
     * content rule (engineConfigViolations) has to scan exactly the text the
     * skeleton stopped covering. When it walked the document itself, the two
     * walks disagreed in three ways, each letting a forbidden key ride in a span
     * nothing checked: this walk SKIPS the NODE_CONFIG_YAML body (so a decoy
     * sentinel planted there captured a second walk while the skeleton digest
     * stayed identical), it lifts EVERY engine span (a scan stopping at the
     * first left the rest unread), and it REFUSES a malformed document (a scan
     * returning "absent" reported no violations for it).
     */
    engineBodies: string[]
}

/**
 * Splits the measured compose text into the parts an operator may vary and the
 * structure they may not, returning the structure with the varying spans
 * replaced by fixed placeholders, plus the image reference it lifted out.
 *
 * WHY A SKELETON RATHER THAN A YAML PARSE. The rules a verifier wants —
 * published image, no host bind mounts, no privileged, ports limited to 9090 —
 * all read structure out of a YAML document, and implementing that twice means
 * two YAML parsers deciding a security question about the same bytes. Parsers
 * disagree (anchors, merge keys, duplicate keys, quoting), and a disagreement
 * here is not a crash: it is the proxy and this client reaching opposite
 * verdicts on identical evidence, silently.
 *
 * Comparing the structure against a published release inverts the problem.
 * Nothing has to enumerate what is forbidden, because everything not in the
 * release's own compose is forbidden by construction — a bind mount, a
 * `privileged: true`, a second service, an added port, a `command:` override
 * are all just text the skeleton does not contain. The cost is rigidity: an
 * operator who reformats their compose no longer matches. That is deliberate.
 *
 * A SECOND `image:` IS NOT LIFTED — it stays in the skeleton as literal text,
 * and it MUST be pinned by digest (`unpinned_sidecar`). That combination is a
 * stronger pin than lifting it, not a weaker one; either half alone is a hole.
 * Literal-but-unpinned would hold one stable skeleton digest over any bytes the
 * operator later supplies through `${VAR}` — dstack hashes this document before
 * expansion — which is exactly the attack `trustedNodeImages` stops for the
 * first image. Pinned-but-lifted is the next paragraph. The sealed_local rung
 * runs an inference engine as that sidecar, so the document has two images and
 * this used to refuse it outright. Lifting the engine too would
 * mean two references checked against one flat `trustedNodeImages` list, where a
 * released ENGINE image would pass as a released NODE image — the confusion a
 * flat list invites. Leaving it literal means the release's own engine digest is
 * part of the structure an operator may not vary: bump the engine and it is a
 * node release, which is the correct coupling for something that sees plaintext
 * prompts.
 *
 * "First" is well-defined here for the same reason the rest of the design works:
 * the skeleton is compared byte-for-byte against a published digest, so
 * reordering the services, swapping the engine digest, or adding a third one all
 * change the skeleton and stop matching. An attacker who puts their own image
 * first has it lifted and checked against the release list, which refuses it.
 *
 * The block-scalar walk is the only subtle part, and it follows YAML's own
 * rule: the scalar runs to the first following line that is neither blank nor
 * indented deeper than the key. Consuming too FEW lines is safe — the leftovers
 * stay in the skeleton and it stops matching. Consuming too MANY would be a
 * hole, because real compose directives would be swallowed into the span nobody
 * checks, so the walk must never be loosened past that rule.
 *
 * A tab in a line's leading whitespace is refused outright: YAML forbids tab
 * indentation, and it makes "indented deeper" ambiguous — exactly the ambiguity
 * the paragraph above depends on not existing.
 *
 * Mirrors `attest.ExtractComposeSkeleton` in Go.
 */
export function extractComposeSkeleton(dockerCompose: string): ComposeSkeleton {
    const lines = dockerCompose.split('\n')
    const out: string[] = []
    let imageRef = ''

    // Armed by the `zs-engine-config:` sentinel and disarmed by the very next
    // non-blank line, whatever it is. The narrow window is the safety property:
    // a `content:` that is not the one directly under the sentinel is never
    // lifted, so the generic key cannot swallow a span nobody checks.
    let engineArmed = false
    let engineSentinelIndent = 0
    const engineBodies: string[] = []

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? ''
        const indent = leadingSpace(line)
        if (indent.includes('\t')) {
            throw new ComposeSkeletonError(
                'tab_indent',
                `docker_compose_file indents with a tab (line ${i + 1})`,
            )
        }

        if (engineArmed) {
            if (trimAscii(line) === '') {
                out.push(line)
                continue
            }
            const engineDepth = composeEngineConfigBlockStart(line, engineSentinelIndent)
            if (engineDepth !== null) {
                engineArmed = false
                out.push(`${line.replace(/ +$/, '')}\n${SKELETON_ENGINE_CONFIG_PLACEHOLDER}`)
                const end = consumeBlockScalar(lines, i, engineDepth)
                // EVERY span is collected, not just the first. The walk lifts
                // them all, so a scan reading only one would leave the rest
                // outside both the measurement and the content rule.
                if (end > i) engineBodies.push(lines.slice(i + 1, end + 1).join('\n'))
                i = end
                continue
            }
            engineArmed = false
        }

        // ONLY THE FIRST image is lifted; every later one stays in the skeleton
        // as literal text. See the "second image" paragraph in the doc comment
        // for why that is a pin rather than a gap.
        const ref = composeImageRef(line)
        if (ref !== null) {
            if (imageRef === '') {
                imageRef = ref
                out.push(`${indent}image: ${SKELETON_IMAGE_PLACEHOLDER}`)
                continue
            }
            // A later image is checked against no release list, so its literal
            // bytes are the whole pin — and a `${VAR}` or a tag is not a pin.
            // dstack hashes this document BEFORE expanding `${VAR}`, so a
            // release written that way would publish one skeleton digest under
            // which the operator runs any engine they like, in the process that
            // sees plaintext prompts.
            if (!isDigestPinnedRef(ref)) {
                throw new ComposeSkeletonError(
                    'unpinned_sidecar',
                    `docker_compose_file declares a second image that is not pinned by digest: ${JSON.stringify(ref)} (line ${i + 1})`,
                )
            }
            out.push(line)
            continue
        }

        const depth = composeConfigBlockStart(line)
        if (depth !== null) {
            out.push(`${line.replace(/ +$/, '')}\n${SKELETON_CONFIG_PLACEHOLDER}`)
            i = consumeBlockScalar(lines, i, depth)
            continue
        }

        const sentinel = composeEngineConfigSentinel(line)
        if (sentinel !== null) {
            engineArmed = true
            engineSentinelIndent = sentinel
        }

        out.push(line)
    }

    if (imageRef === '') {
        throw new ComposeSkeletonError('no_image', 'docker_compose_file declares no image')
    }
    return { skeleton: out.join('\n'), imageRef, engineBodies }
}

/** sha256 of a skeleton, lowercase hex — the value a release list holds. */
export function composeSkeletonDigest(skeleton: string): string {
    return bytesToHex(sha256(new TextEncoder().encode(skeleton)))
}

/**
 * A line's indentation verbatim, tabs included, so the caller can refuse them
 * rather than silently measuring a tab as one column.
 */
function leadingSpace(line: string): string {
    const m = /^[ \t]*/.exec(line)
    return m ? m[0] : ''
}

/**
 * Reports whether ref names immutable bytes: `<repository>@sha256:<64 lowercase
 * hex>`.
 *
 * Hand-rolled rather than a regexp for the same reason nothing in this file
 * parses YAML — one rule, spelled identically in Go and TS, with no engine
 * between the two that could disagree about it. Lowercase-only is deliberate:
 * the digest a registry serves is lowercase, and accepting both cases would let
 * two spellings of one reference produce two skeletons.
 *
 * `${` ANYWHERE IN THE REFERENCE IS REFUSED, including in the repository half.
 * dstack hashes docker_compose_file BEFORE expanding `${VAR}`, so an
 * interpolated reference is not a value this document pins — it is a value the
 * operator supplies afterwards, out of the measurement. The digest half being
 * literal would still content-address the bytes, so an interpolated repository
 * is not by itself an escape; it is refused because the rule this function
 * exists to enforce is spelled `<repository>@sha256:<hex>` in SPEC §5, no
 * registry accepts `${` in a repository name, and a check that admitted it
 * would make three documents' worth of "a `${VAR}` is not a pin" false.
 *
 * Mirrors `attest.isDigestPinnedRef` in Go.
 */
function isDigestPinnedRef(ref: string): boolean {
    if (ref.includes('${')) return false
    const at = ref.indexOf('@sha256:')
    if (at <= 0) return false
    const digest = ref.slice(at + '@sha256:'.length)
    if (digest.length !== 64) return false
    for (let i = 0; i < digest.length; i++) {
        const c = digest.charCodeAt(i)
        const isDigit = c >= 0x30 && c <= 0x39
        const isLowerHex = c >= 0x61 && c <= 0x66
        if (!isDigit && !isLowerHex) return false
    }
    return true
}

/**
 * Matches a bare `image: <ref>` line, returning null when it is not one.
 *
 * Deliberately strict about shape — no quotes, no trailing comment. Anything
 * else fails to match, so the line stays literal in the skeleton and the digest
 * comparison refuses it. That is the right outcome: the operator is expected to
 * have copied a published compose, and a reformatted one is not it.
 */
function composeImageRef(line: string): string | null {
    const trimmed = line.replace(/^ +/, '')
    if (!trimmed.startsWith('image:')) return null
    const ref = trimAscii(trimmed.slice('image:'.length))
    if (ref === '' || /[ \t#]/.test(ref)) return null
    return ref
}

/**
 * The engine-config settings a measured deployment may not declare.
 *
 * WHY THESE TWO AND NOTHING ELSE. The engine config span is LIFTED out of the
 * skeleton so an operator can size the runtime for their own hardware — context
 * window, sequence count, GPU layers, cache types. Those are choices about
 * throughput and cannot change what the model says. These two can:
 * `adapters` attaches LoRA adapters, changing behaviour while every byte of the
 * weights stays exactly what the digest reports; `template` replaces the jinja
 * chat template, the same problem reached through formatting. The weights chain
 * has no view of either.
 */
const ENGINE_CONFIG_FORBIDDEN_KEYS = ['adapters', 'template'] as const

/**
 * Returns the settings an engine-config span may not declare. A fresh array
 * each call: the caller cannot edit the rule.
 */
export function engineConfigForbiddenKeys(): string[] {
    return [...ENGINE_CONFIG_FORBIDDEN_KEYS]
}

/**
 * Returns the forbidden keys a compose's engine-config spans declare, in the
 * order engineConfigForbiddenKeys lists them. Empty means acceptable.
 *
 * IT SCANS THE SPANS THE SKELETON LIFTED, taken straight from
 * extractComposeSkeleton, and never re-walks the document. The reason is on
 * ComposeSkeleton.engineBodies: a second walk disagreed with the lift in three
 * ways, and each disagreement was a forbidden key riding in text nothing
 * checked.
 *
 * A DOCUMENT THAT CANNOT BE TAKEN APART IS A VIOLATION, not an absence. The
 * content rule runs even when enforceComposeSkeleton is off, so under the
 * shipped policy it is the only thing looking at this document; a tab anywhere
 * in the file used to make the walk report "no span" and produce nothing.
 */
export function engineConfigViolations(dockerCompose: string): string[] {
    if (isBlank(dockerCompose)) return []
    let extracted: ComposeSkeleton
    try {
        extracted = extractComposeSkeleton(dockerCompose)
    } catch {
        // A refusal here means the walk never reached the spans, so this rule
        // cannot say the document is clean. But it may only blame the ENGINE
        // CONFIG for a document that has one: a compose declaring no image is
        // malformed for reasons the skeleton path reports far better, and
        // answering it with "your engine config is wrong" sends the operator
        // somewhere there is nothing to find.
        //
        // The test is a substring, not a walk — a document with no sentinel
        // anywhere cannot contain a span, since the lift requires that exact
        // key. Conservative in the direction that matters.
        return dockerCompose.includes(COMPOSE_ENGINE_CONFIG_KEY) ? ['unparseable-compose'] : []
    }
    return ENGINE_CONFIG_FORBIDDEN_KEYS.filter((k) =>
        extracted.engineBodies.some((body) => engineConfigMentions(body, k)),
    )
}

/**
 * Reports whether a lifted span mentions a forbidden key at all.
 *
 * A CASE-INSENSITIVE SUBSTRING TEST, DELIBERATELY, and the bluntness is the
 * point. An earlier version tried to recognise the key in the positions a YAML
 * mapping key can occupy — start of a trimmed line, or after `{` or `,`. Every
 * one of these is also a legal way to write the same key, and all walked
 * straight through it:
 *
 *     adapters : [x]          a space before the colon; YAML drops it
 *     adapters\t: [x]         a tab, likewise
 *     - adapters: [x]         a block-sequence entry
 *     m: [adapters: [x]]      a flow sequence of single-pair maps
 *     "\x61dapters": [x]      a double-quoted hex escape, schema-independent
 *     ? adapters              an explicit key
 *
 * Enumerating key positions means enumerating YAML, which is the thing this
 * module refuses to do in front of a security question. A substring test has no
 * positions to miss. It over-refuses, including on a comment mentioning the
 * word, and that is the accepted cost.
 */
function engineConfigMentions(body: string, key: string): boolean {
    return body.toLowerCase().includes(key)
}

/**
 * Matches `NODE_CONFIG_YAML: |` (with any block-scalar chomping indicator),
 * returning the key's indentation depth, or null.
 */
function composeConfigBlockStart(line: string): number | null {
    return blockScalarStart(line, COMPOSE_CONFIG_KEY)
}

/**
 * Matches the bare `zs-engine-config:` key line that must immediately precede
 * the engine config's `content:` block, returning its indentation depth.
 *
 * The key must have NOTHING after the colon: a value on the same line is not
 * the shape this lifts, and treating it as one would arm the lift on a document
 * whose next `content:` belongs to something else entirely.
 */
function composeEngineConfigSentinel(line: string): number | null {
    const trimmed = line.replace(/^ +/, '')
    const prefix = `${COMPOSE_ENGINE_CONFIG_KEY}:`
    if (!trimmed.startsWith(prefix)) return null
    if (trimAscii(trimmed.slice(prefix.length)) !== '') return null
    return line.length - trimmed.length
}

/**
 * Matches the `content: |` line carrying the engine configuration, given the
 * indent of the sentinel that armed it. The content key must be indented DEEPER
 * than the sentinel, or it is not inside that entry at all.
 */
function composeEngineConfigBlockStart(line: string, sentinelIndent: number): number | null {
    const depth = blockScalarStart(line, 'content')
    if (depth === null || depth <= sentinelIndent) return null
    return depth
}

/**
 * Matches `<key>: |` (with any block-scalar chomping indicator), returning the
 * key's indentation depth. Shared so the two lifted scalars cannot drift on
 * which indicators they accept — a document one of them took apart and the
 * other did not would produce two skeletons for one file.
 */
function blockScalarStart(line: string, key: string): number | null {
    const trimmed = line.replace(/^ +/, '')
    const prefix = `${key}:`
    if (!trimmed.startsWith(prefix)) return null
    const rest = trimAscii(trimmed.slice(prefix.length))
    if (!['|', '|-', '|+', '>', '>-', '>+'].includes(rest)) return null
    return line.length - trimmed.length
}

/**
 * Returns the index of the LAST line belonging to the block scalar whose key
 * sits at line index `start` with indentation `depth`.
 *
 * Blank lines belong to the scalar whatever their own indentation — YAML's
 * rule, and treating one as a terminator would end the span early on any config
 * containing a paragraph break. Consuming too FEW lines is safe (the leftovers
 * stay in the skeleton and it stops matching); consuming too MANY is a hole,
 * because real compose directives would land in a span nobody checks.
 */
function consumeBlockScalar(lines: string[], start: number, depth: number): number {
    let i = start
    while (i + 1 < lines.length) {
        const next = lines[i + 1] ?? ''
        if (trimAscii(next) === '') {
            i++
            continue
        }
        const ni = leadingSpace(next)
        if (ni.includes('\t')) {
            throw new ComposeSkeletonError(
                'tab_indent',
                `docker_compose_file indents with a tab (line ${i + 2})`,
            )
        }
        if (ni.length <= depth) break
        i++
    }
    return i
}

/**
 * Reports whether an already-uppercased env NAME ends in one of the policy's
 * permitted suffixes.
 *
 * The two guards carry the whole safety of it, and neither is defensive
 * programming: an empty suffix makes `endsWith` true for every name, and a
 * suffix not anchored on `_` matches any name merely ending in those letters (a
 * bare `KEY` would admit half the config surface). Skipping a malformed entry
 * rather than honouring it keeps a typo from widening the policy silently.
 */
function hasAllowedSuffix(p: ComposePolicy, upperName: string): boolean {
    for (const s of p.allowedEnvSuffixes ?? []) {
        const up = trimAscii(s).toUpperCase()
        if (up === '' || !up.startsWith('_')) continue
        if (upperName.endsWith(up)) return true
    }
    return false
}

/**
 * The ONLY whitespace class anything in this file trims, and naming it is the
 * point — `String.prototype.trim` must not appear here.
 *
 * JS's `trim` uses its own WhiteSpace ∪ LineTerminator set; Go's
 * `strings.TrimSpace` uses `unicode.IsSpace`. The two DISAGREE, in both
 * directions: U+0085 (NEL) is space to Go and not to JS, U+FEFF (BOM) is space
 * to JS and not to Go. Borrowing either language's notion therefore builds a
 * verdict split into a byte-exact security gate — measured, not theorized. With
 * a `docker_compose_file` of exactly one U+0085 Go reported
 * `empty_docker_compose` and this file accepted the document; with one U+FEFF
 * the two swapped. The same split moved the skeleton digest and flipped the
 * image-reference match.
 *
 * That matters most where it is cheapest to overlook: `empty_docker_compose` is
 * the ONLY rule guarding `docker_compose_file` while consumers ship
 * `enforceComposeSkeleton` false, and a vacuous compose is the shape this
 * module exists to refuse.
 *
 * ASCII-only, deliberately: YAML's own "empty line" is spaces and tabs, the
 * walk already refuses tabs in indentation, and every value compared here (a
 * hex digest, an env name, an image reference) is ASCII by construction.
 * Anything exotic is then content — the fail-CLOSED direction, since it
 * survives the trim, fails to match, and is refused rather than accepted.
 *
 * Mirrors `trimASCII` in go/attest/compose.go byte for byte; change neither
 * alone.
 */
const ASCII_SPACE = /^[ \t\n\v\f\r]+|[ \t\n\v\f\r]+$/g

function trimAscii(s: string): string {
    return s.replace(ASCII_SPACE, '')
}

/**
 * The UNION of JavaScript's trim set and Go's `unicode.IsSpace`, plus the two
 * codepoints where they disagree. It answers exactly one question — "does this
 * compose contain nothing at all?" — and is deliberately the opposite extreme
 * from `ASCII_SPACE` above.
 *
 * The two point in opposite directions because fail-closed means opposite
 * things for them. Normalizing a VALUE (an env name, a hex digest, an image
 * reference) must trim as LITTLE as possible: anything exotic left in place
 * fails to match its allowlist and the node is refused. Deciding a document is
 * VACUOUS must trim as MUCH as possible: every character that could be nothing
 * must count as nothing, or the rule is sidesteppable.
 *
 * And it was. With only the ASCII class, a `docker_compose_file` of one U+0085
 * verified CLEAN in both languages — agreeing, which was the bug fixed first,
 * but agreeing on the wrong answer. `empty_docker_compose` is the only rule
 * guarding `docker_compose_file` while consumers ship `enforceComposeSkeleton`
 * false, so one invisible character disabled it. The golden vectors caught
 * that; no hand-written test would have, because the fixture nobody thinks to
 * write is the one made of characters nobody can see.
 *
 * Mirrors `blankSpace` / `isBlank` in go/attest/compose.go; change neither
 * alone.
 */
const BLANK_SPACE = new Set([
    0x20, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    0x0085, // NEL — space to Go, not to JS
    0x00a0, // NBSP
    0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007,
    0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
    0xfeff, // BOM — space to JS, not to Go
])

function isBlank(s: string): boolean {
    for (const ch of s) {
        if (!BLANK_SPACE.has(ch.codePointAt(0)!)) return false
    }
    return true
}

/**
 * Lowercases, trims, and strips an `0x` prefix. An empty result is
 * never a match — the property that makes an empty allowlist fail
 * closed.
 */
function normalizeHex(s: string): string {
    const t = trimAscii(s).toLowerCase()
    return t.startsWith('0x') ? t.slice(2) : t
}

/**
 * `containsFold`'s case-SENSITIVE twin, for values where case is meaningful.
 * An image reference is one: registry paths and tags are case-sensitive, so
 * folding them would accept a reference Docker resolves differently — or not
 * at all.
 *
 * Keeps the empty-want rule, which is what makes an empty list fail closed
 * rather than matching a document that declared nothing.
 */
function containsExact(list: readonly string[], want: string): boolean {
    if (trimAscii(want) === '') return false
    return list.some((v) => trimAscii(v) === want)
}

function containsFold(list: readonly string[], want: string): boolean {
    if (!want) return false
    return list.some((x) => {
        const n = normalizeHex(x)
        return n !== '' && n === want
    })
}

function bytesToHex(b: Uint8Array): string {
    let out = ''
    for (const x of b) out += x.toString(16).padStart(2, '0')
    return out
}

function str(v: unknown): string {
    return typeof v === 'string' ? v : ''
}
function num(v: unknown): number {
    return typeof v === 'number' ? v : 0
}
function bool(v: unknown): boolean {
    return v === true
}
function strArray(v: unknown): string[] {
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []
}
