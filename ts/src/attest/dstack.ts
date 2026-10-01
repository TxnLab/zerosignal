/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// TypeScript mirror of proto/go/attest — parsing an Intel TDX quote and
// replaying a dstack runtime event log into RTMR3.
//
// It is here rather than in client/ for the reason the Go package
// header gives, with one more consumer: the node replays its own log at
// mint time so it never publishes evidence no verifier could accept,
// the proxy replays it to decide whether to route, and the browser
// replays it to decide the same thing WITHOUT trusting the proxy. Three
// copies of derivation arithmetic would let a node self-certify under
// rules a relying party does not share, and nothing in any log would
// name the disagreement.
//
// Pinned against proto/go/attest by proto/testdata/attest_vectors.json,
// which is generated from Go and read by both test suites over the same
// capture files. That is not ceremony: every value in here is one a
// wrong implementation reproduces as a well-formed, plausible, and
// entirely incorrect 48 or 32 bytes.
//
// See proto/SPEC.md §3e "Measurement replay".

import { sha256, sha384 } from '@noble/hashes/sha2.js'

// The event type dstack stamps on the runtime events it extends into
// RTMR3.
//
// Matching on it — rather than on `imr === 3` — is what dstack's own
// verifier does (sdk/go/ratls/ratls.go), and the two do NOT select the
// same set. The boot events in IMR 0-2 follow a different digest
// convention entirely, so a replay that filtered by IMR would extend
// events whose digests it computed the wrong way and land on a
// wrong-but-well-formed value.
export const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001

// The width of a TDX runtime measurement register: SHA-384.
const RTMR_LEN = 48

// Named runtime events a verifier gates on. They are read off the
// REPLAYED log, never off any self-reported field.
export const EVENT_COMPOSE_HASH = 'compose-hash'
export const EVENT_OS_IMAGE_HASH = 'os-image-hash'
export const EVENT_APP_ID = 'app-id'
export const EVENT_INSTANCE_ID = 'instance-id'
export const EVENT_KEY_PROVIDER = 'key-provider'

// One entry of a dstack runtime event log.
//
// `digest` is decoded but deliberately never used. dstack leaves it
// EMPTY on every runtime event, so an implementation that reads it
// extends with nothing — the field is kept here only so its emptiness
// is visible to anyone reading the type and wondering where it went.
export interface DstackEvent {
    imr: number
    event_type: number
    digest: string
    event: string
    event_payload: string
}

// AttestError is thrown by the replay for the cases where continuing
// would produce a value a caller could compare. Each `code` corresponds
// to a way the replay yields something plausible and meaningless, and
// each is raised rather than papered over: a caller that compared
// anyway would be comparing two things that agree for the wrong reason.
export type AttestErrorCode =
    /**
     * The log contained no runtime events at all, so the "replayed"
     * value is 48 zero bytes. Against a quote whose RTMR3 is also zero
     * — an uninitialized or simulated register — that compares EQUAL
     * and reads as a pass.
     */
    | 'empty_replay'
    /**
     * At least one runtime event's payload was not hex. Skipping it
     * silently yields a partial replay: a wrong 48-byte value
     * indistinguishable from a correct one.
     */
    | 'undecodable_payload'
    /**
     * The quote's RTMR3 is all zero, which no genuinely measured CVM
     * produces. Comparing against it would let an all-zero replay pass.
     */
    | 'zero_rtmr'
    /**
     * The quote is too short to hold the register the log would be
     * compared against.
     *
     * Its own code rather than a generic failure because this branch
     * fails OPEN under one plausible edit: returning the measurements
     * without raising hands a verifier a compose-hash and an
     * os-image-hash that were compared against nothing at all. The
     * bytes are operator-supplied and reach here after only a length
     * check, so the branch is reachable by anyone.
     */
    | 'short_quote'
    /** The log parsed, replayed, and disagreed with the quote. */
    | 'rtmr3_mismatch'
    /** The raw log was not a JSON array of events. */
    | 'malformed_log'
    /**
     * A key-binding operator id arrived as a `number` too large to be
     * exact. See reportData — the silent alternative is a valid-looking
     * hash of a different id.
     */
    | 'unsafe_operator_id'
    /**
     * Same hazard as unsafe_operator_id, for the node id that enters the
     * aux binding. See auxBinding.
     */
    | 'unsafe_node_id'
    /**
     * An H_app entry is not an object, lacks a key, carries a null, or has
     * a value of the wrong type. Mirrors Go's ErrMalformedModelEntry, which
     * inject.ModelEntry's strict decoder produces.
     */
    | 'malformed_model_entry'
    /**
     * The bundle's posture is not an object, or one of its fields has the
     * wrong type. Go's decoder refuses such a bundle outright; this refuses
     * it at hPosture.
     */
    | 'malformed_posture'
    /**
     * Two H_app entries name one model (compared as UTF-8 bytes). A minter
     * and a verifier that kept different ones would compute different
     * digests.
     */
    | 'duplicate_model_id'
    /** An H_app entry has no model id, so nothing can match it to a request. */
    | 'empty_model_id'
    /**
     * An unverifiable entry carries a digest, or a measured or declared
     * entry carries none.
     */
    | 'state_digest_disagree'
    /**
     * A weights state this build does not know, including 0. Refused so a
     * newer node's state is never hashed as one this verifier thinks it
     * understands.
     */
    | 'unknown_weights_state'
    /**
     * A fixed-width input to auxBinding arrived at the wrong width — an
     * H_app digest or a nonce that is not 32 bytes.
     *
     * Its own code because Go cannot reach either condition at all
     * ([32]byte and *[32]byte make them unrepresentable), so no golden
     * vector pins them and nothing else would catch the spelling drifting.
     */
    | 'invalid_aux_input'
    /**
     * The quote is too short to carry a report_data field — a malformed
     * or truncated quote. See splitReportData.
     *
     * Distinct from short_quote, which is about the register a log is
     * replayed against: this one says the binding itself is unreadable.
     */
    | 'report_data_absent'
    /**
     * report_data's upper 32 bytes are all zero, which is what a pre-9.9
     * node mints. Verifiers report it as aux_binding_absent so the
     * operator sees that the node needs an upgrade.
     */
    | 'aux_binding_absent'
    /**
     * The signed aux binding is not auxBinding(nodeId, hApp(entries),
     * nonce): the catalog, the node id or the nonce differs. See verifyAux.
     */
    | 'aux_binding_mismatch'
    /**
     * The bundle lists no models, and the signed aux binding is not the
     * empty-catalog value for this node and nonce. See verifyAux.
     */
    | 'happ_preimage_missing'
    /**
     * The verifier sent a challenge and the bundle's nonce is absent,
     * malformed, or a different value. See verifyAux.
     */
    | 'nonce_mismatch'
    /**
     * The verifier sent no challenge and the bundle's nonce is present but
     * is not 64 hex characters. See verifyAux.
     */
    | 'malformed_nonce'
    /**
     * The verifier's own challenge is all zero, which hashes the same as no
     * challenge, so a cached bundle with a 64-zero nonce field would pass as
     * fresh. Seen only from a verifier bug. See verifyAux.
     */
    | 'zero_challenge'

export class AttestError extends Error {
    readonly code: AttestErrorCode

    constructor(code: AttestErrorCode, message: string) {
        super(message)
        this.name = 'AttestError'
        this.code = code
    }
}

// Both cases, matching Go's hex.DecodeString, which accepts either.
const HEX_RE = /^[0-9a-fA-F]*$/

// LOWERCASE `0x` ONLY, because Go's strings.TrimPrefix(s, "0x") is
// lowercase-only and this mirror follows the canonical implementation
// rather than improving on it.
//
// Accepting `0X` here looked like harmless leniency and was a live
// divergence: the event log is operator-authored, so a payload of
// "0Xab" decoded in the browser and failed in the node and the proxy —
// two relying parties reaching OPPOSITE verdicts on identical evidence,
// which is the exact failure the shared module exists to prevent. Real
// dstack emits no prefix at all, so nothing observable was wrong; that
// is what made it worth pinning rather than shrugging at. The hostile
// vectors carry both spellings so the two suites go red together.
const HEX_PREFIX = '0x'

function hexToBytes(hex: string): Uint8Array {
    const s = hex.startsWith(HEX_PREFIX) ? hex.slice(2) : hex
    if (s.length % 2 !== 0 || !HEX_RE.test(s)) {
        throw new Error(`not hex: ${s.length} chars`)
    }
    const out = new Uint8Array(s.length / 2)
    for (let i = 0; i < out.length; i++) {
        out[i] = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16)
    }
    return out
}

function bytesToHex(b: Uint8Array): string {
    let out = ''
    for (const c of b) out += c.toString(16).padStart(2, '0')
    return out
}

function allZero(b: Uint8Array): boolean {
    for (const c of b) if (c !== 0) return false
    return true
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
    return true
}

function concat(...parts: Uint8Array[]): Uint8Array {
    let n = 0
    for (const p of parts) n += p.length
    const out = new Uint8Array(n)
    let off = 0
    for (const p of parts) {
        out.set(p, off)
        off += p.length
    }
    return out
}

const utf8 = new TextEncoder()

/** parseEventLog decodes the raw JSON array carried as the bundle's `event_log`. */
export function parseEventLog(raw: string): DstackEvent[] {
    let parsed: unknown
    try {
        parsed = JSON.parse(raw)
    } catch (e) {
        throw new AttestError('malformed_log', `attest: event log is not JSON: ${String(e)}`)
    }
    if (!Array.isArray(parsed)) {
        throw new AttestError('malformed_log', 'attest: event log is not a JSON array of events')
    }
    return parsed as DstackEvent[]
}

export interface ReplayResult {
    /** The recomputed 48-byte RTMR3. */
    value: Uint8Array
    /** How many events were folded in, for callers logging the shape of what they verified. */
    extends: number
}

/**
 * replayRTMR3 recomputes RTMR3 from a dstack event log, following
 * dstack's rule exactly (sdk/go/ratls/ratls.go verifyRTMR3, matching the
 * Rust cc_eventlog::runtime_events::replay_events::<Sha384>):
 *
 *     digest = SHA-384( le32(event_type) || ":" || event || ":" || payload )
 *     rtmr   = SHA-384( rtmr || digest )       from 48 zero bytes
 *
 * THE PER-EVENT DIGEST IS COMPUTED, NOT READ. dstack leaves the log's
 * own `digest` field empty on every runtime event — measured on a live
 * CVM 2026-08-25, where all ten matching entries carried "digest":"".
 * An implementation that trusts that field extends with nothing and
 * lands on a wrong-but-well-formed 48-byte value: on that capture it
 * produced 7e1f442b… where the truth was 1fa4f8ce… — an EARLIER capture
 * than the one now in testdata, so don't look for those two values
 * there. Nothing throws, the
 * value is the right length, and the verifier reports a mismatch it will
 * be believed about. That is the failure this comment exists to stop
 * recurring, and the golden vectors are what make it detectable.
 *
 * event_type is little-endian because TDX CVMs are x86_64 and dstack
 * packs it with to_ne_bytes(); the payload is hex in the JSON and hashed
 * as raw bytes.
 */
export function replayRTMR3(events: DstackEvent[]): ReplayResult {
    let acc = new Uint8Array(RTMR_LEN)
    let extendCount = 0

    for (const [i, e] of events.entries()) {
        if (e.event_type !== DSTACK_RUNTIME_EVENT_TYPE) continue

        let payload: Uint8Array
        try {
            payload = hexToBytes(e.event_payload ?? '')
        } catch (err) {
            throw new AttestError(
                'undecodable_payload',
                `attest: event log has an undecodable event payload: event ${i} (${JSON.stringify(e.event)}): ${String(err)}`,
            )
        }

        const et = new Uint8Array(4)
        new DataView(et.buffer).setUint32(0, e.event_type, true) // little-endian

        const digest = sha384(concat(et, utf8.encode(':'), utf8.encode(e.event ?? ''), utf8.encode(':'), payload))
        acc = sha384(concat(acc, digest))
        extendCount++
    }

    if (extendCount === 0) {
        throw new AttestError('empty_replay', 'attest: event log extended zero runtime events')
    }
    return { value: acc, extends: extendCount }
}

/**
 * runtimeMeasurements collects the named runtime events into a map keyed
 * by event name, with hex payloads lowercased and unprefixed.
 *
 * A duplicate name keeps the FIRST occurrence. dstack emits each once,
 * so a second is either a platform change worth noticing or an attempt
 * to have a later, friendlier value win a lookup; keeping the first
 * means an appended event cannot displace a measured one.
 */
export function runtimeMeasurements(events: DstackEvent[]): Record<string, string> {
    const out: Record<string, string> = {}
    for (const e of events) {
        if (e.event_type !== DSTACK_RUNTIME_EVENT_TYPE || !e.event) continue
        if (Object.hasOwn(out, e.event)) continue
        // Same lowercase-only prefix rule as hexToBytes, and for the
        // same reason: Go trims "0x" then lowercases, so on "0Xab" both
        // sides must end up with "0xab" rather than one of them with
        // "ab". A measurement string that differs between implementations
        // is compared against the same allowlist by both.
        const p = e.event_payload ?? ''
        out[e.event] = (p.startsWith(HEX_PREFIX) ? p.slice(2) : p).toLowerCase()
    }
    return out
}

/**
 * verifyEventLog is the whole check as one call: parse the log, replay
 * it, and confirm the result equals the RTMR3 the hardware signed inside
 * the quote. On success it returns the named runtime events the replay
 * covered, which is the ONLY sanctioned source for compose-hash and
 * os-image-hash — reading them from anywhere else skips the step that
 * makes them mean anything.
 *
 * The all-zero RTMR3 guard is here rather than at the call site because
 * that is where it is load-bearing: an empty replay and an unmeasured
 * register agree, and a caller doing a plain equality check has no way
 * to notice.
 */
export function verifyEventLog(rawLog: string, quote: Uint8Array): Record<string, string> {
    const events = parseEventLog(rawLog)
    const { value: replayed } = replayRTMR3(events)

    const fromQuote = quoteRTMR(quote, 3)
    if (!fromQuote) {
        throw new AttestError('short_quote', `attest: quote is too short to hold RTMR3: got ${quote.length} bytes`)
    }
    if (allZero(fromQuote)) {
        throw new AttestError('zero_rtmr', "attest: quote's RTMR3 is all zero")
    }
    if (!bytesEqual(replayed, fromQuote)) {
        throw new AttestError(
            'rtmr3_mismatch',
            `attest: RTMR3 replay does not match the quote (replayed ${bytesToHex(replayed)}, quote ${bytesToHex(fromQuote)})`,
        )
    }
    return runtimeMeasurements(events)
}

// ---------------------------------------------------------------------------
// TDX v4 quote field access
// ---------------------------------------------------------------------------

// TDX v4 quote layout: a 48-byte header followed by the TD report body.
// Offsets are into the body.
const QUOTE_HEADER_LEN = 48
const BODY_MRTD = 136
const BODY_RTMR0 = 328
const BODY_REPORT_DATA = 520

// The offset of the 4-byte TEE type in the quote HEADER (not the body).
const HEADER_TEE_TYPE = 4

/** The header's tee_type value for Intel TDX. 0x00 is SGX. */
export const TEE_TYPE_TDX = 0x81

/**
 * The width of the hardware REPORTDATA field. Each of the two bindings
 * it carries is 32 bytes — see splitReportData.
 */
export const REPORT_DATA_LEN = 64

/**
 * quoteTEEType reads the TEE type from the quote header, or null when
 * the quote is too short.
 *
 * This is how a verifier decides which vendor chain to check the quote
 * against. It must never be decided by the bundle's `mode` string: that
 * is node-authored, so reading it would hand the operator the choice of
 * which chain their evidence is judged against.
 */
export function quoteTEEType(quote: Uint8Array): number | null {
    if (quote.length < HEADER_TEE_TYPE + 4) return null
    return new DataView(quote.buffer, quote.byteOffset + HEADER_TEE_TYPE, 4).getUint32(0, true)
}

/** quoteRTMR extracts RTMR[n] (n in 0..3) from a TDX v4 quote. */
export function quoteRTMR(quote: Uint8Array, n: number): Uint8Array | null {
    if (!Number.isInteger(n) || n < 0 || n > 3) return null
    const off = QUOTE_HEADER_LEN + BODY_RTMR0 + n * RTMR_LEN
    if (quote.length < off + RTMR_LEN) return null
    return quote.subarray(off, off + RTMR_LEN)
}

/** quoteMRTD extracts MRTD, the CVM's initial-measurement register. */
export function quoteMRTD(quote: Uint8Array): Uint8Array | null {
    const off = QUOTE_HEADER_LEN + BODY_MRTD
    if (quote.length < off + RTMR_LEN) return null
    return quote.subarray(off, off + RTMR_LEN)
}

/** quoteReportData extracts the full 64-byte REPORTDATA field. */
export function quoteReportData(quote: Uint8Array): Uint8Array | null {
    const off = QUOTE_HEADER_LEN + BODY_REPORT_DATA
    if (quote.length < off + REPORT_DATA_LEN) return null
    return quote.subarray(off, off + REPORT_DATA_LEN)
}

/**
 * The 64-byte hardware field split into the two independent commitments
 * it carries. Mirrors Go's attest.ReportDataHalves.
 *
 * Named fields rather than a tuple: both halves are 32-byte Uint8Arrays,
 * so a caller that swaps them still type-checks.
 */
export interface ReportDataHalves {
    /**
     * The lower 32 bytes: SHA-256(ephemeral age pubkey ||
     * be64(operator_id)). Compare against reportData, recomputed from a
     * key and an id resolved INDEPENDENTLY of the bundle.
     */
    keyBinding: Uint8Array
    /**
     * The upper 32 bytes: SHA-256 over the node id, H_app and the nonce.
     * splitReportData checks only that it is not all zero; verifyAux
     * checks its value against the bundle.
     */
    auxBinding: Uint8Array
}

/**
 * Thrown by splitReportData for an all-zero upper half. Carries the lower
 * half, like Go's SplitReportData returning KeyBinding with
 * ErrAuxBindingAbsent, so a verifier checks the key binding first; a quote
 * whose key binding is also wrong is reported as key_binding_mismatch.
 */
export class AuxBindingAbsentError extends AttestError {
    readonly keyBinding: Uint8Array

    constructor(keyBinding: Uint8Array) {
        super('aux_binding_absent', 'attest: report_data upper half is all zero — node predates proto 9.9')
        this.name = 'AuxBindingAbsentError'
        this.keyBinding = keyBinding
    }
}

/**
 * splitReportData returns both halves of report_data. Mirrors Go's
 * SplitReportData.
 *
 * It throws report_data_absent for a quote too short to hold the field,
 * and AuxBindingAbsentError for an all-zero upper half. There is no option
 * to accept a zero upper half, so no input can select pre-9.9 behaviour.
 *
 * A non-zero upper half is only known to be populated. Before 9.9 the upper
 * half had to be zero, because the quote signature covers all 64 bytes and
 * an unchecked half would let a node get 32 bytes of its choice signed by
 * real hardware. That protection now depends on the caller calling
 * verifyAux.
 */
export function splitReportData(quote: Uint8Array): ReportDataHalves {
    const rd = quoteReportData(quote)
    if (!rd) {
        throw new AttestError('report_data_absent', 'attest: quote carries no report_data field')
    }
    if (allZero(rd.subarray(32))) {
        throw new AuxBindingAbsentError(rd.slice(0, 32))
    }
    // COPIED, not subarray views. rd is itself a view into the caller's
    // quote, so returning views would let a caller that reuses or zeroizes
    // that buffer change these halves underneath a comparison. Go returns
    // [32]byte values and cannot have this problem; quotePCKCertChain
    // copies for the same reason.
    return { keyBinding: rd.slice(0, 32), auxBinding: rd.slice(32) }
}

// ---------------------------------------------------------------------------
// Key binding
// ---------------------------------------------------------------------------

/**
 * reportData computes the binding nonce a TEE embeds in its report's
 * report_data field:
 *
 *     report_data = SHA-256(node_pubkey_bytes || operator_id_be64)
 *
 * The operator id is big-endian so the digest input has one canonical
 * form across implementations — a bigint here rather than a number
 * because operator ids are uint64 and Number loses precision above 2^53,
 * which would silently produce the right-shaped wrong hash.
 *
 * nodePubkey is the node's current **ephemeral age recipient** — the key
 * requests are actually sealed to. It is deliberately NOT the on-chain
 * signing address: attesting the identity key would prove only that the
 * enclave controls the operator identity, leaving the hop from that key
 * to the sealing key operator-attested (an Ed25519 advertisement
 * signature nothing proves was produced inside the CVM). An operator
 * holding a copy of the signing key outside the enclave could then point
 * traffic at an ephemeral whose private half lives on the plain host and
 * still pass every check.
 *
 * Mirrors proto/go/attest.ReportData; see proto/SPEC.md §3e. A mismatch
 * is the `key_binding_mismatch` failure tag in proto/TEE.md §4.3.
 *
 * A `number` argument above Number.MAX_SAFE_INTEGER THROWS rather than
 * hashing. `operator_id` rides the evidence bundle as a JSON number, so
 * JSON.parse hands a browser a float64 — and past 2^53 that is a
 * DIFFERENT id, which hashes to a valid-looking 32 bytes that will never
 * match the quote. The verdict would be `key_binding_mismatch` against
 * an operator whose evidence is perfectly good, with the arithmetic in
 * this file blamed for a rounding error three layers up. Ids are
 * allocated from a sequential counter so this is not reachable today;
 * it is guarded because the failure is silent and the guard is free.
 * Callers holding a real uint64 should pass a bigint.
 *
 * A NEGATIVE id throws too, in either representation. The uint64 mask
 * below would otherwise turn -1 into the max-uint64 hash — the single
 * most confusing possible wrong answer, since it is a real id's real
 * digest. Go cannot express the case at all (the parameter is uint64),
 * so there is nothing to mirror and the mask exists only to make the
 * bigint path total; rejecting is what keeps it from being a coercion.
 *
 * The predicate is Number.isSafeInteger and not a `> MAX_SAFE_INTEGER`
 * range check: the latter admits fractional ids, which reach BigInt()
 * and throw a bare RangeError carrying no `code`, so a caller switching
 * on AttestErrorCode gets an unhandled exception instead of a verdict.
 */
export function reportData(nodePubkey: string, operatorId: bigint | number): Uint8Array {
    if (operatorId < 0) {
        throw new AttestError(
            'unsafe_operator_id',
            `attest: operator id ${operatorId} is negative — ids are uint64`,
        )
    }
    if (typeof operatorId === 'number' && !Number.isSafeInteger(operatorId)) {
        throw new AttestError(
            'unsafe_operator_id',
            `attest: operator id ${operatorId} cannot be represented exactly as a number — pass a bigint`,
        )
    }
    const id = BigInt(operatorId) & 0xffffffffffffffffn
    const idBytes = new Uint8Array(8)
    new DataView(idBytes.buffer).setBigUint64(0, id, false) // big-endian
    return sha256(concat(utf8.encode(nodePubkey), idBytes))
}

/** reportDataB64 is reportData in the standard-base64 form the bundle's `report_data` field carries. */
export function reportDataB64(nodePubkey: string, operatorId: bigint | number): string {
    return bytesToBase64(reportData(nodePubkey, operatorId))
}

function bytesToBase64(b: Uint8Array): string {
    let s = ''
    for (const c of b) s += String.fromCharCode(c)
    return btoa(s)
}

// ---------------------------------------------------------------------------
// Aux binding — the UPPER 32 bytes of report_data
//
// reportData above is the lower half. The upper half commits to the node id,
// the model catalog the node advertises, and an optional caller nonce.
// Mirrors proto/go/attest/binding.go, pinned by
// proto/testdata/attest_vectors.json (h_app, h_app_json, aux_binding,
// aux_verify).
// ---------------------------------------------------------------------------

// Domain tags. Each ends in NUL and contains no other NUL, so no tag is a
// prefix of another. The aux tag moved to v2 when H_posture joined the
// preimage (9.10).
const AUX_BINDING_TAG = 'zs-aux-v2\x00'
const H_APP_TAG = 'zs-happ-v1\x00'
const H_POSTURE_TAG = 'zs-posture-v1\x00'

/**
 * The bundle's `posture` block as parsed. Mirrors Go's inject.TEEPosture,
 * snake_case for the same reason ModelEntry is. Optional fields are absent
 * on the wire when empty (Go's omitempty).
 */
export interface TEEPosture {
    plaintext_terminates?: string
    upstream_base_url?: string
    zero_retention?: boolean
    upstream_attested?: boolean
}

// A boolean field as Go's decoder leaves it: absent and null are both false.
function postureBool(v: unknown, name: string): boolean {
    if (v === undefined || v === null) return false
    if (typeof v !== 'boolean') {
        throw new AttestError('malformed_posture', `attest: posture ${name} is not a boolean`)
    }
    return v
}

// A string field as Go's decoder leaves it: absent and null are both ''.
function postureString(v: unknown): string {
    if (v === undefined || v === null) return ''
    if (typeof v !== 'string') {
        throw new AttestError('malformed_posture', 'attest: posture field is not a string')
    }
    return v
}

/**
 * hPosture is the measurement of the node's dataflow posture. Mirrors Go's
 * HPosture:
 *
 *     absent:  SHA-256( "zs-posture-v1\0" || u8(0) )
 *     present: SHA-256( "zs-posture-v1\0" || u8(1) || lenStr(plaintext_terminates)
 *                       || lenStr(upstream_base_url) || u8(zero_retention)
 *                       || u8(upstream_attested) )
 *
 * It is what makes the upstream a verifier judges the one the measured binary
 * derived, rather than a self-report anything on the path could rewrite.
 * null and undefined are absent, as Go decodes a JSON null into a nil
 * pointer; inside the object a null field is its zero value, as Go leaves it.
 * Unknown keys are ignored, as both decoders do.
 */
export function hPosture(posture: unknown): Uint8Array {
    if (posture === undefined || posture === null) {
        return sha256(concat(utf8.encode(H_POSTURE_TAG), new Uint8Array([0])))
    }
    if (typeof posture !== 'object' || Array.isArray(posture)) {
        throw new AttestError('malformed_posture', 'attest: posture is not an object')
    }
    const r = posture as Record<string, unknown>
    const terminates = postureString(r['plaintext_terminates'])
    const upstream = postureString(r['upstream_base_url'])
    const zr = postureBool(r['zero_retention'], 'zero_retention')
    const attested = postureBool(r['upstream_attested'], 'upstream_attested')
    return sha256(
        concat(
            utf8.encode(H_POSTURE_TAG),
            new Uint8Array([1]),
            lenBytes(utf8.encode(terminates)),
            lenBytes(utf8.encode(upstream)),
            new Uint8Array([zr ? 1 : 0, attested ? 1 : 0]),
        ),
    )
}

/**
 * What an entry's weights digest is based on. Mirrors Go's WeightsState.
 * Measured and declared digests are the same kind of string, so without
 * this field a verifier could not tell a hash the node computed from one
 * the operator typed into its config.
 *
 * Zero is not a state: hApp refuses it, so a missing or defaulted value
 * never reads as Measured.
 */
export const WeightsState = {
    /** Code inside the node hashed the weight files, or took the digest from a runtime that reports what it loaded. */
    Measured: 1,
    /** The operator pinned the digest in config and the node did not confirm it. */
    Declared: 2,
    /** No digest. Hosted passthrough, image models and gated repos are normally in this state, and it is a valid entry. */
    Unverifiable: 3,
} as const

export type WeightsStateValue = (typeof WeightsState)[keyof typeof WeightsState]

/**
 * One advertised model as it enters H_app. Mirrors Go's inject.ModelEntry.
 *
 * Snake_case because it is the bundle's `app_models` entry as parsed. A
 * verifier hashes the parsed object directly; a camelCase copy would need a
 * conversion step that could drop a field and still type-check.
 *
 * The type describes what a node sends. hApp does not trust it: a bundle is
 * parsed JSON, so hApp checks every field's runtime type.
 */
export interface ModelEntry {
    /** The id the node advertises and a caller puts in `model`. */
    model_id: string
    /** Provenance ref (a HuggingFace repo, typically); empty when unresolved. */
    source: string
    /**
     * `sha256:<hex>`, or empty for Unverifiable. The format is not
     * validated: an attacker would send a well-formed digest of the wrong
     * bytes, so checking the shape would catch nothing.
     */
    weights_digest: string
    /** What the digest is based on. */
    weights_state: WeightsStateValue
}

// One entry after the runtime type checks, with its strings UTF-8 encoded.
// Sorting, duplicate detection and hashing all use these bytes, so a lone
// surrogate (which TextEncoder writes as U+FFFD, as Go's JSON decoder does)
// compares the same way in both implementations.
interface EncodedEntry {
    id: Uint8Array
    source: Uint8Array
    digest: Uint8Array
    state: number
    label: string
}

function encodeEntry(e: unknown): EncodedEntry {
    if (typeof e !== 'object' || e === null || Array.isArray(e)) {
        throw new AttestError('malformed_model_entry', 'attest: model entry is not an object')
    }
    const r = e as Record<string, unknown>
    const { model_id, source, weights_digest, weights_state } = r
    if (
        typeof model_id !== 'string' ||
        typeof source !== 'string' ||
        typeof weights_digest !== 'string' ||
        typeof weights_state !== 'number' ||
        !Number.isInteger(weights_state)
    ) {
        throw new AttestError(
            'malformed_model_entry',
            'attest: model entry lacks a key, carries a null, or has a value of the wrong type',
        )
    }
    return {
        id: utf8.encode(model_id),
        source: utf8.encode(source),
        digest: utf8.encode(weights_digest),
        state: weights_state,
        label: model_id,
    }
}

/**
 * hApp is the measurement of the model set:
 *
 *     H_app = SHA-256( "zs-happ-v1\0" || be32(len(entries)) || entry... )
 *     entry = lenStr(model_id) || lenStr(source) || lenStr(weights_digest) || u8(state)
 *
 * A node MUST list its complete advertised catalog: a node that listed only
 * the models it could hash could serve an unlisted one and still verify. The
 * list can lag /v1/zs/details by about 75 s after a catalog change, so the
 * reference verifiers report it and do not route on it.
 *
 * Checks run in the same order as Go's HApp, so both report the same error
 * for the same list. hApp first rejects any malformed entry
 * (malformed_model_entry), scanning in the caller's order, then stable-sorts
 * by UTF-8 model_id bytes, then checks each sorted entry for an empty id, a
 * duplicate id, and a state/digest disagreement. The sort compares UTF-8
 * bytes, not UTF-16 code units with `<`, because the two order ids outside
 * the BMP differently. The caller's array is not mutated.
 *
 * An empty list is valid; see hAppPending. null and undefined count as
 * empty, as Go decodes a JSON null into a nil slice.
 */
export function hApp(entries: readonly ModelEntry[] | null | undefined): Uint8Array {
    entries ??= []
    if (!Array.isArray(entries)) {
        throw new AttestError('malformed_model_entry', 'attest: app_models is not an array')
    }
    const encoded = (entries as readonly unknown[]).map(encodeEntry)
    const sorted = [...encoded].sort((a, b) => compareBytes(a.id, b.id))

    const parts: Uint8Array[] = [utf8.encode(H_APP_TAG), u32(sorted.length)]

    for (let i = 0; i < sorted.length; i++) {
        const e = sorted[i]!
        if (e.id.length === 0) {
            throw new AttestError('empty_model_id', 'attest: entry has an empty model id')
        }
        // Duplicates are adjacent after the sort.
        if (i > 0 && compareBytes(e.id, sorted[i - 1]!.id) === 0) {
            throw new AttestError(
                'duplicate_model_id',
                `attest: duplicate model id in the entry list: ${e.label}`,
            )
        }
        switch (e.state) {
            case WeightsState.Measured:
            case WeightsState.Declared:
                if (e.digest.length === 0) {
                    throw new AttestError(
                        'state_digest_disagree',
                        `attest: ${e.label} has state ${e.state} with no digest`,
                    )
                }
                break
            case WeightsState.Unverifiable:
                if (e.digest.length !== 0) {
                    throw new AttestError(
                        'state_digest_disagree',
                        `attest: ${e.label} is unverifiable yet carries a digest`,
                    )
                }
                break
            default:
                throw new AttestError('unknown_weights_state', `attest: ${e.label} has state ${e.state}`)
        }
        parts.push(lenBytes(e.id), lenBytes(e.source), lenBytes(e.digest))
        // No mask: the switch above has already established the state is
        // 1, 2 or 3.
        parts.push(new Uint8Array([e.state]))
    }
    return sha256(concat(...parts))
}

/**
 * hAppPending is the H_app of an empty entry list. A node publishes it until
 * its catalog is available to the minter.
 *
 * It is not zero, so auxBinding over it is not zero either, and
 * splitReportData does not mistake a booting node for a pre-9.9 one. A
 * bundle carrying it verifies and lists no models.
 */
export function hAppPending(): Uint8Array {
    return hApp([])
}

/**
 * auxBinding is the upper 32 bytes of report_data:
 *
 *     aux_binding = SHA-256( "zs-aux-v2\0" || be64(node_id) || H_app || H_posture || nonce )
 *
 * node_id is here so a node cannot present a sibling node's bundle: the
 * lower half hashes operator_id only. It is be64, like operator_id in
 * reportData; a decimal string would give "0042" and "42" different
 * preimages.
 *
 * A null nonce hashes as 32 zero bytes, as does an explicit all-zero nonce.
 *
 * Throws on a nonce, H_app or H_posture that is not exactly 32 bytes, and on
 * a node id passed as a number above Number.MAX_SAFE_INTEGER, which a number
 * cannot hold exactly. Pass the chain-resolved id as a bigint.
 */
export function auxBinding(
    nodeId: bigint | number,
    hAppDigest: Uint8Array,
    hPostureDigest: Uint8Array,
    nonce: Uint8Array | null,
): Uint8Array {
    if (nodeId < 0) {
        throw new AttestError('unsafe_node_id', `attest: node id ${nodeId} is negative — ids are uint64`)
    }
    if (typeof nodeId === 'number' && !Number.isSafeInteger(nodeId)) {
        throw new AttestError(
            'unsafe_node_id',
            `attest: node id ${nodeId} cannot be represented exactly as a number — pass a bigint`,
        )
    }
    if (hAppDigest.length !== 32) {
        throw new AttestError(
            'invalid_aux_input',
            `attest: H_app must be 32 bytes, got ${hAppDigest.length}`,
        )
    }
    if (hPostureDigest.length !== 32) {
        throw new AttestError(
            'invalid_aux_input',
            `attest: H_posture must be 32 bytes, got ${hPostureDigest.length}`,
        )
    }
    if (nonce !== null && nonce.length !== 32) {
        throw new AttestError('invalid_aux_input', `attest: nonce must be 32 bytes, got ${nonce.length}`)
    }
    // The mask makes the bigint path total, matching reportData's. It
    // silently truncates a bigint at or above 2^64 — a value Go's uint64
    // parameter cannot express, so there is nothing to mirror and nothing a
    // vector could pin. Kept identical to reportData rather than made
    // stricter: two adjacent id encodings differing on their out-of-range
    // behaviour is a worse trap than either rule on its own.
    const id = BigInt(nodeId) & 0xffffffffffffffffn
    const idBytes = new Uint8Array(8)
    new DataView(idBytes.buffer).setBigUint64(0, id, false) // big-endian
    return sha256(
        concat(utf8.encode(AUX_BINDING_TAG), idBytes, hAppDigest, hPostureDigest, nonce ?? new Uint8Array(32)),
    )
}

/**
 * verifyAux recomputes the aux binding from a bundle and compares it with
 * the upper half the hardware signed. Mirrors Go's
 * ReportDataHalves.VerifyAux; the aux_verify vectors pin that the two make
 * the same decision. Throws an AttestError; returns nothing on success.
 *
 * nodeId MUST be the chain-resolved id. The bundle does not carry one.
 *
 * entries is the bundle's app_models as parsed; null or undefined counts
 * as empty. posture is the bundle's posture as parsed; null or undefined is
 * absent. A verifier MUST judge the same posture value it passed here — a
 * copy read from anywhere else is unbound again.
 *
 * echoed is the bundle's nonce field as parsed: null, undefined and '' all
 * mean absent. It is typed unknown because it comes from untrusted JSON; a
 * value that is not a string fails the same way a malformed string does.
 * challenge is the nonce this verifier sent with ?nonce=, or null:
 *
 *   - challenge set: it must not be all zero (zero_challenge), and echoed
 *     must decode to it (nonce_mismatch otherwise). challenge is hashed.
 *   - challenge null, echoed absent: 32 zero bytes are hashed.
 *   - challenge null, echoed set: echoed must be 64 hex characters
 *     (malformed_nonce otherwise), and its bytes are hashed. A bundle
 *     minted for someone else's challenge therefore still verifies; a
 *     verifier that wants freshness has to send its own.
 *
 * Errors, in the order they are checked: zero_challenge, nonce_mismatch or
 * malformed_nonce; an hApp error; malformed_posture; then
 * happ_preimage_missing if entries is empty and the binding differs, else
 * aux_binding_mismatch.
 */
export function verifyAux(
    halves: ReportDataHalves,
    nodeId: bigint | number,
    entries: readonly ModelEntry[] | null | undefined,
    posture: unknown,
    echoed: unknown,
    challenge: Uint8Array | null,
): void {
    entries ??= []
    const nonce = resolveNonce(echoed, challenge)
    const hAppDigest = hApp(entries)
    const want = auxBinding(nodeId, hAppDigest, hPosture(posture), nonce)
    const got = halves.auxBinding
    let diff = got.length ^ want.length
    for (let i = 0; i < want.length; i++) diff |= (got[i] ?? 0) ^ (want[i] ?? 0)
    if (diff === 0) return
    if (entries.length === 0) {
        throw new AttestError(
            'happ_preimage_missing',
            'attest: bundle lists no models but the quote does not commit to an empty catalog',
        )
    }
    throw new AttestError(
        'aux_binding_mismatch',
        'attest: aux binding does not match node id, catalog, posture and nonce',
    )
}

function resolveNonce(echoed: unknown, challenge: Uint8Array | null): Uint8Array | null {
    if (challenge !== null) {
        if (challenge.length === 32 && challenge.every((b) => b === 0)) {
            throw new AttestError('zero_challenge', 'attest: challenge is all zero')
        }
        const got = decodeNonce(echoed)
        if (got === null || challenge.length !== 32 || !bytesEqual(got, challenge)) {
            throw new AttestError('nonce_mismatch', 'attest: bundle nonce does not echo the challenge')
        }
        return challenge
    }
    if (echoed === '' || echoed == null) return null
    const got = decodeNonce(echoed)
    if (got === null) {
        throw new AttestError('malformed_nonce', 'attest: bundle nonce is not 64 hex characters')
    }
    return got
}

// Exactly 64 hex characters, either case, no 0x prefix. Matches Go's
// decodeNonce.
const NONCE_RE = /^[0-9a-fA-F]{64}$/

// The typeof check comes first: RegExp.test stringifies its argument, so
// ["<64 hex>"] would otherwise pass and then break hexToBytes.
function decodeNonce(s: unknown): Uint8Array | null {
    return typeof s === 'string' && NONCE_RE.test(s) ? hexToBytes(s) : null
}

/**
 * parseEvidenceBundle decodes a /v1/zs/attestation response body. Use it in
 * place of `res.json()` or `res.text()`.
 *
 * Both of those replace invalid UTF-8 with U+FFFD, one per maximal subpart,
 * while Go's decoder writes one per bad byte. A model id carrying bad bytes
 * would therefore hash differently here and in Go, so this refuses the body
 * instead, as Go's TEEEvidenceBundle.UnmarshalJSON does. A byte-order mark is
 * kept rather than stripped, so JSON.parse refuses it as Go does.
 *
 * Throws a TypeError on invalid UTF-8 and a SyntaxError on invalid JSON.
 */
export function parseEvidenceBundle(body: Uint8Array | ArrayBuffer): unknown {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(body))
}

/** Failure tags for the aux binding (SPEC §3e, verifier step 6). */
export const AuxFailureTag = {
    AuxBindingAbsent: 'aux_binding_absent',
    AuxBindingMismatch: 'aux_binding_mismatch',
    HAppPreimageMissing: 'happ_preimage_missing',
    HAppPreimageInvalid: 'happ_preimage_invalid',
    PosturePreimageInvalid: 'posture_preimage_invalid',
} as const

export type AuxFailureTagValue = (typeof AuxFailureTag)[keyof typeof AuxFailureTag]

/**
 * auxFailureTag maps an error from splitReportData's aux check or from
 * verifyAux to its SPEC failure tag. Mirrors Go's AuxFailureTag. Any error
 * it does not recognise maps to aux_binding_mismatch, so it still refuses.
 *
 * Handle report_data_absent before calling it: SPEC tags a quote too short
 * to hold report_data key_binding_mismatch, which is not an aux tag.
 */
export function auxFailureTag(err: unknown): AuxFailureTagValue {
    const code = err instanceof AttestError ? err.code : undefined
    switch (code) {
        case 'aux_binding_absent':
            return AuxFailureTag.AuxBindingAbsent
        case 'happ_preimage_missing':
            return AuxFailureTag.HAppPreimageMissing
        case 'malformed_model_entry':
        case 'duplicate_model_id':
        case 'empty_model_id':
        case 'state_digest_disagree':
        case 'unknown_weights_state':
            return AuxFailureTag.HAppPreimageInvalid
        case 'malformed_posture':
            return AuxFailureTag.PosturePreimageInvalid
        default:
            return AuxFailureTag.AuxBindingMismatch
    }
}

// Orders byte strings the way Go's `<` on strings does.
function compareBytes(a: Uint8Array, b: Uint8Array): number {
    const n = Math.min(a.length, b.length)
    for (let i = 0; i < n; i++) {
        if (a[i]! !== b[i]!) return a[i]! < b[i]! ? -1 : 1
    }
    return a.length === b.length ? 0 : a.length < b.length ? -1 : 1
}

// u32 / lenBytes mirror proto/go/attest/binding.go's appendU32 /
// appendLenStr. The length is the UTF-8 byte length.
function u32(v: number): Uint8Array {
    const buf = new Uint8Array(4)
    new DataView(buf.buffer).setUint32(0, v, false)
    return buf
}

function lenBytes(body: Uint8Array): Uint8Array {
    return concat(u32(body.length), body)
}

/** Exported for callers that need the hex form of a register or digest. */
export { bytesToHex as attestBytesToHex, hexToBytes as attestHexToBytes }
