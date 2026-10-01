/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Cross-impl parity for TEE measurement arithmetic, against
// proto/testdata/attest_vectors.json (produced by
// `cd proto/go && go test ./attest -run TestVectors -update`).
//
// The inputs are the SAME two capture files the Go test reads — a real
// Phala tdx.small CVM's event log and the quote minted in the same call
// — referenced by path out of the vectors file rather than inlined, so
// the two implementations cannot end up agreeing about different bytes.
//
// This matters more than a usual parity suite. Every value here is one
// a wrong implementation reproduces as a well-formed, plausible, and
// entirely incorrect 48 or 32 bytes: SHA-384 of the wrong preimage is
// still 48 bytes, a little-endian operator id still hashes to 32, and a
// replay that trusted the log's own empty `digest` field lands on a
// perfectly-shaped value that is not the register. Nothing throws in
// any of those cases; the only thing that catches them is agreeing with
// hardware-signed bytes.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import {
    AttestError,
    AuxBindingAbsentError,
    DSTACK_RUNTIME_EVENT_TYPE,
    REPORT_DATA_LEN,
    TEE_TYPE_TDX,
    attestBytesToHex,
    attestHexToBytes,
    auxBinding,
    auxFailureTag,
    hApp,
    hAppPending,
    hPosture,
    parseEvidenceBundle,
    parseEventLog,
    quoteMRTD,
    quoteRTMR,
    quoteReportData,
    quoteTEEType,
    replayRTMR3,
    reportData,
    reportDataB64,
    runtimeMeasurements,
    splitReportData,
    verifyAux,
    verifyEventLog,
} from '../src/attest/index.js'
import type { DstackEvent, ModelEntry, WeightsStateValue } from '../src/attest/index.js'

/** Returns a copy of `b` with one bit of byte `i` flipped. */
function flipBit(b: Uint8Array, i: number): Uint8Array {
    const out = Uint8Array.from(b)
    out[i] = (out[i] ?? 0) ^ 0x01
    return out
}

/** Whether the quote's report_data upper half is all zero (the pre-9.9 shape). */
function allZeroUpper(quote: Uint8Array): boolean {
    return quote.subarray(48 + 520 + 32, 48 + 520 + 64).every((b) => b === 0)
}

/**
 * Returns a copy of `quote` with the upper 32 bytes of report_data
 * replaced. The result is NOT signature-valid — see the caller. Mirrors
 * withAuxHalf in proto/go/attest/dstack_test.go.
 */
function withAuxHalf(quote: Uint8Array, aux: Uint8Array): Uint8Array {
    const out = Uint8Array.from(quote)
    out.set(aux, 48 + 520 + 32)
    return out
}

interface ReportDataVector {
    name: string
    node_pubkey: string
    /** A decimal string, not a number — see the Go vector struct for why. */
    operator_id: string
    expected_hex: string
    expected_b64: string
}

interface HostileCase {
    name: string
    why: string
    log: string
    /** '' when Go's replay succeeded. */
    replay_error: string
    rtmr3_hex: string
    extends: number
    measurements: Record<string, string>
}

interface Vectors {
    version: number
    comment: string
    event_log_path: string
    quote_path: string
    runtime_event_type: number
    replay: { extends: number; rtmr3_hex: string }
    measurements: Record<string, string>
    quote: {
        len: number
        tee_type: number
        mrtd_hex: string
        rtmr0_hex: string
        rtmr1_hex: string
        rtmr2_hex: string
        rtmr3_hex: string
        report_data_hex: string
        binding_hash_hex: string
        split_error: string
        binding_node_pubkey: string
        binding_operator_id: string
    }
    report_data: ReportDataVector[]
    h_app: HAppVector[]
    aux_binding: AuxBindingVector[]
    h_app_json: HAppJSONVector[]
    aux_verify: AuxVerifyVector[]
    h_posture: HPostureVector[]
    hostile: HostileCase[]
}

interface HPostureVector {
    name: string
    why: string
    /** Raw JSON text; '' means the posture field is absent from the bundle. */
    posture_json: string
    expected_hex: string
}

interface HAppJSONVector {
    name: string
    why: string
    /** Raw JSON text, parsed here with JSON.parse as a verifier would. */
    entries_json: string
    error: string
    expected_hex: string
}

interface AuxVerifyVector {
    name: string
    why: string
    node_id: string
    /** '' means app_models is absent from the bundle. */
    entries_json: string
    /** '' means posture is absent from the bundle. */
    posture_json: string
    /** '' means the bundle carries no nonce. */
    echoed_nonce: string
    /** '' means the verifier sent no challenge. */
    challenge_hex: string
    aux_hex: string
    error: string
    tag: string
}

interface HAppVector {
    name: string
    why: string
    entries: { model_id: string; source: string; weights_digest: string; weights_state: number }[]
    error: string
    expected_hex: string
}

interface AuxBindingVector {
    name: string
    why: string
    node_id: string
    h_app_hex: string
    h_posture_hex: string
    nonce_hex: string
    expected_hex: string
}

const here = path.dirname(fileURLToPath(import.meta.url))
const testdataDir = path.resolve(here, '../../testdata')

const vectors: Vectors = JSON.parse(fs.readFileSync(path.join(testdataDir, 'attest_vectors.json'), 'utf8'))

// The H_posture of a bundle with no posture field, for tests whose subject is
// some other input to the aux binding.
const NO_POSTURE = hPosture(undefined)

const rawLog = fs.readFileSync(path.join(testdataDir, vectors.event_log_path), 'utf8')
const quote = attestHexToBytes(fs.readFileSync(path.join(testdataDir, vectors.quote_path), 'utf8').trim())

describe('attest vectors', () => {
    // The vectors file names its own inputs. If that indirection ever
    // breaks, every assertion below would run against whatever files
    // happened to be there — so check the shape before trusting it.
    it('reads the same capture the Go suite reads', () => {
        expect(vectors.event_log_path).toBe('attest/ds_event_log.json')
        expect(vectors.quote_path).toBe('attest/ds_quote_hex.txt')
        expect(quote.length).toBe(vectors.quote.len)
    })

    it('agrees on the runtime event type', () => {
        expect(DSTACK_RUNTIME_EVENT_TYPE).toBe(vectors.runtime_event_type)
    })

    it('replays the event log to the quote-signed RTMR3', () => {
        const events = parseEventLog(rawLog)
        const { value, extends: n } = replayRTMR3(events)

        expect(n).toBe(vectors.replay.extends)
        expect(attestBytesToHex(value)).toBe(vectors.replay.rtmr3_hex)

        // The replayed value and the register read out of the quote are
        // pinned as separate fields in the vectors file precisely so
        // this can be asserted: one is computed, the other is read, and
        // they agree only if the computation is right.
        expect(vectors.replay.rtmr3_hex).toBe(vectors.quote.rtmr3_hex)
    })

    it('replays exactly the runtime events, not every event', () => {
        const events = parseEventLog(rawLog)
        // The capture has more events than it extends. A replay that
        // folded in all of them produces a 48-byte value too.
        expect(events.length).toBeGreaterThan(vectors.replay.extends)
    })

    it('recovers the named measurements', () => {
        expect(runtimeMeasurements(parseEventLog(rawLog))).toEqual(vectors.measurements)
    })

    it('verifyEventLog returns the measurements for a matching quote', () => {
        expect(verifyEventLog(rawLog, quote)).toEqual(vectors.measurements)
    })

    it('reads the TDX quote fields', () => {
        expect(quoteTEEType(quote)).toBe(vectors.quote.tee_type)
        expect(quoteTEEType(quote)).toBe(TEE_TYPE_TDX)
        expect(attestBytesToHex(quoteMRTD(quote)!)).toBe(vectors.quote.mrtd_hex)
        expect(attestBytesToHex(quoteRTMR(quote, 0)!)).toBe(vectors.quote.rtmr0_hex)
        expect(attestBytesToHex(quoteRTMR(quote, 1)!)).toBe(vectors.quote.rtmr1_hex)
        expect(attestBytesToHex(quoteRTMR(quote, 2)!)).toBe(vectors.quote.rtmr2_hex)
        expect(attestBytesToHex(quoteRTMR(quote, 3)!)).toBe(vectors.quote.rtmr3_hex)
        expect(attestBytesToHex(quoteReportData(quote)!)).toBe(vectors.quote.report_data_hex)
        expect(quoteReportData(quote)!.length).toBe(REPORT_DATA_LEN)
    })

    it('refuses the pre-9.9 capture, naming the flag day rather than a crypto failure', () => {
        // The capture came from a pre-9.9 node, so its upper half is zero
        // padding and 9.9 refuses it. The vectors record which refusal, so
        // Go and TS must agree on the code, not only on refusing.
        expect(vectors.quote.split_error).toBe('aux_binding_absent')
        let thrown: unknown
        try {
            splitReportData(quote)
        } catch (err) {
            thrown = err
        }
        expect(thrown, 'splitReportData accepted a zero upper half').toBeInstanceOf(AuxBindingAbsentError)
        expect((thrown as AttestError).code).toBe(vectors.quote.split_error)
        // The lower half comes with the refusal, so a verifier can check the
        // key binding before reporting an out-of-date node.
        expect(attestBytesToHex((thrown as AuxBindingAbsentError).keyBinding)).toBe(vectors.quote.binding_hash_hex)
    })

    it('splits both halves of a populated report_data', () => {
        // SYNTHETIC: splicing an aux binding in invalidates the quote
        // signature, so this is for the byte-level split only and must
        // never reach signature or collateral verification. Mirrors the
        // Go test of the same shape.
        const aux = auxBinding(42n, hAppPending(), NO_POSTURE, null)
        const synthetic = withAuxHalf(quote, aux)

        const halves = splitReportData(synthetic)
        // THE VALUES, not the widths. Both halves are 32 bytes, so a
        // split returning them swapped is indistinguishable by length.
        expect(attestBytesToHex(halves.keyBinding)).toBe(vectors.quote.binding_hash_hex)
        expect(attestBytesToHex(halves.auxBinding)).toBe(attestBytesToHex(aux))

        // EVERY byte of the upper half — the mirror of the pre-9.9
        // version of this loop, which asserted the opposite. Narrowing
        // the zero scan to the first four bytes would wrongly REFUSE a
        // node whose aux binding happens to start with four zeros, which
        // presents as an unroutable node with a crypto error.
        for (let i = 32; i < 64; i++) {
            const probe = flipBit(quote, 48 + 520 + i)
            const h = splitReportData(probe)
            // The exact byte, matching the Go mirror: `!= 0` would also
            // pass if the split returned a shifted window.
            expect(h.auxBinding[i - 32], `upper byte ${i}`).toBe(0x01)
        }
    })

    it('computes the key binding identically to Go', () => {
        expect(vectors.report_data.length).toBeGreaterThan(0)
        for (const c of vectors.report_data) {
            const id = BigInt(c.operator_id)
            expect(attestBytesToHex(reportData(c.node_pubkey, id)), c.name).toBe(c.expected_hex)
            expect(reportDataB64(c.node_pubkey, id), c.name).toBe(c.expected_b64)
        }
        // The suite is only worth anything if it covers ids a float64
        // cannot hold — that case is what caught the encoding.
        expect(vectors.report_data.some((c) => BigInt(c.operator_id) > BigInt(Number.MAX_SAFE_INTEGER))).toBe(true)
    })

    it('refuses an operator id that arrived as an imprecise number', () => {
        // The failure this prevents is silent: JSON.parse turns a
        // uint64 bundle field into a float64, and hashing the rounded
        // value yields a perfectly well-formed 32 bytes that can never
        // match the quote — reported as key_binding_mismatch against an
        // operator whose evidence is fine.
        expect(() => reportData('k', Number.MAX_SAFE_INTEGER + 2)).toThrowError(
            expect.objectContaining({ code: 'unsafe_operator_id' }) as unknown as Error,
        )

        // A FRACTIONAL id, which a `> MAX_SAFE_INTEGER` range check
        // would admit. It reaches BigInt() and throws a bare RangeError
        // carrying no `code`, so a caller switching on AttestErrorCode
        // — the entire point of that union — gets an unhandled
        // exception instead of a verdict.
        expect(() => reportData('k', 1.5)).toThrowError(
            expect.objectContaining({ code: 'unsafe_operator_id' }) as unknown as Error,
        )

        // A NEGATIVE id in either representation. The uint64 mask would
        // otherwise turn -1 into the max-uint64 hash: a real id's real
        // digest, which is the most confusing possible wrong answer.
        expect(() => reportData('k', -1)).toThrowError(
            expect.objectContaining({ code: 'unsafe_operator_id' }) as unknown as Error,
        )
        expect(() => reportData('k', -1n)).toThrowError(
            expect.objectContaining({ code: 'unsafe_operator_id' }) as unknown as Error,
        )

        // ...and a safe number must still work, or the guard is just a
        // ban on the `number` overload.
        expect(attestBytesToHex(reportData('k', 1))).toBe(attestBytesToHex(reportData('k', 1n)))
        expect(attestBytesToHex(reportData('k', 0))).toBe(attestBytesToHex(reportData('k', 0n)))
    })

    it('encodes the operator id big-endian', () => {
        // Two ids that are byte-reverses of each other: under
        // little-endian encoding each produces the OTHER's big-endian
        // digest, so a swapped implementation makes these equal.
        const a = reportData('k', 0x0102030405060708n)
        const b = reportData('k', 0x0807060504030201n)
        expect(attestBytesToHex(a)).not.toBe(attestBytesToHex(b))

        // Derived outside both implementations —
        // `printf 'k'; printf '\x00'x7 '\x01' | shasum -a 256` — because
        // an expectation computed by the code under test agrees with
        // whatever encoding that code happens to use. Same constant the
        // Go suite pins.
        expect(attestBytesToHex(reportData('k', 1n))).toBe(
            'bb5098ab9baf09f4138439a6ce2991b82388005ecf32a36281a2400bcd115136',
        )
    })

    // The capture describes itself now: the file carries the
    // (pubkey, operator_id) that produced the quote's binding hash, so a
    // third implementation can calibrate against real hardware-signed
    // bytes rather than against Go test constants it cannot read.
    //
    // It is also the evidence that a dstack guest agent places a
    // caller-chosen value in REPORTDATA VERBATIM rather than hashing it —
    // recomputing to the quote's own lower half is what rules a hashing
    // agent out.
    it('reproduces the captured quote binding from the inputs the file publishes', () => {
        // Read the field directly rather than through splitReportData,
        // which refuses this pre-9.9 capture. The evidence here is about
        // the LOWER half, which the flag day does not touch.
        const rd = quoteReportData(quote)!
        expect(attestBytesToHex(rd.subarray(0, 32))).toBe(vectors.quote.binding_hash_hex)
        expect(
            attestBytesToHex(
                reportData(vectors.quote.binding_node_pubkey, BigInt(vectors.quote.binding_operator_id)),
            ),
        ).toBe(vectors.quote.binding_hash_hex)
    })
})

// ---------------------------------------------------------------------------
// Aux binding — the upper 32 bytes of report_data
// ---------------------------------------------------------------------------

describe('h_app vectors', () => {
    // NO FIELD MAPPING, deliberately. The vectors carry the wire entries
    // verbatim and ModelEntry is that same shape, so this is a cast and
    // not a rename. A mapping step here would mean the suite proved that
    // hashing a TRANSCRIPTION of the bundle gives the right digest, which
    // is the one thing a verifier never does.
    function toEntries(v: HAppVector): ModelEntry[] {
        return v.entries.map((e) => ({
            ...e,
            weights_state: e.weights_state as WeightsStateValue,
        }))
    }

    it('has both successes and refusals, so neither arm can vanish', () => {
        expect(vectors.h_app.length).toBeGreaterThan(0)
        expect(vectors.h_app.some((c) => c.error === '')).toBe(true)
        expect(vectors.h_app.some((c) => c.error !== '')).toBe(true)
    })

    for (const c of vectors.h_app) {
        if (c.error === '') {
            it(`computes H_app identically to Go: ${c.name}`, () => {
                expect(attestBytesToHex(hApp(toEntries(c)))).toBe(c.expected_hex)
            })
        } else {
            // The refusals are as load-bearing as the successes. A mirror
            // that accepts a duplicate model id computes a digest for a
            // catalog Go would never sign, and the divergence surfaces as a
            // verifier rejecting a node its own operator can verify.
            it(`refuses what Go refuses, with the same code: ${c.name}`, () => {
                // The caught error is hoisted out of the try rather than
                // asserted inside it: an expect() that fails in the try block
                // is itself caught by the adjacent catch, so the real
                // complaint ("hApp accepted what Go refused") is replaced by
                // a confusing "expected undefined to be an AttestError".
                let thrown: unknown
                try {
                    hApp(toEntries(c))
                } catch (err) {
                    thrown = err
                }
                expect(thrown, `hApp accepted an input Go refused with ${c.error}`).toBeInstanceOf(
                    AttestError,
                )
                expect((thrown as AttestError).code).toBe(c.error)
            })
        }
    }

    // Stated as a property rather than left implicit in two vectors that
    // happen to match: a node builds its catalog from maps and discovery
    // order, so if input order changed the digest a node and a verifier
    // holding identical sets would disagree with nothing to diagnose it.
    it('is independent of the caller order, and does not mutate the caller array', () => {
        const entries: ModelEntry[] = [
            { model_id: 'ccc', source: 's', weights_digest: 'sha256:ab', weights_state: 1 },
            { model_id: 'aaa', source: 's', weights_digest: 'sha256:ab', weights_state: 1 },
        ]
        const reversed = [...entries].reverse()
        expect(attestBytesToHex(hApp(entries))).toBe(attestBytesToHex(hApp(reversed)))
        expect(entries[0]!.model_id).toBe('ccc')
    })

    // A zero pending value would make a booting node's upper half look
    // like a pre-9.9 node's, and it would be refused. Asserted here as
    // well as in Go because the vectors only show that the two agree.
    it('has a pending value that is neither zero nor distinct from the empty catalog', () => {
        const pending = hAppPending()
        expect(pending.length).toBe(32)
        expect(pending.every((b) => b === 0)).toBe(false)
        expect(attestBytesToHex(hApp([]))).toBe(attestBytesToHex(pending))
    })
})

// Entry lists as raw JSON, parsed by JSON.parse exactly as a verifier
// parses a bundle. h_app's entries come from Go structs and always carry
// every key; these carry the shapes a hostile node can send.
describe('h_app_json vectors', () => {
    it('includes a malformed entry and an accepted one', () => {
        expect(vectors.h_app_json.some((c) => c.error === 'malformed_model_entry')).toBe(true)
        expect(vectors.h_app_json.some((c) => c.error === '')).toBe(true)
    })

    for (const c of vectors.h_app_json) {
        it(`matches Go on raw JSON: ${c.name}`, () => {
            const entries = JSON.parse(c.entries_json) as ModelEntry[]
            let got: string | undefined
            let thrown: unknown
            try {
                got = attestBytesToHex(hApp(entries))
            } catch (err) {
                thrown = err
            }
            if (c.error === '') {
                expect(thrown).toBeUndefined()
                expect(got).toBe(c.expected_hex)
            } else {
                expect(thrown, `hApp accepted an input Go refused with ${c.error}`).toBeInstanceOf(AttestError)
                expect((thrown as AttestError).code).toBe(c.error)
            }
        })
    }
})

// VerifyAux's decision, not just its arithmetic: the nonce rules, the
// empty-list rule and the failure tag.
describe('aux_verify vectors', () => {
    it('covers every aux tag verifyAux can produce, and a pass', () => {
        const tags = new Set(vectors.aux_verify.map((c) => c.tag))
        for (const t of ['', 'aux_binding_mismatch', 'happ_preimage_missing', 'happ_preimage_invalid']) {
            expect(tags.has(t), t).toBe(true)
        }
    })

    for (const c of vectors.aux_verify) {
        it(`decides as Go does: ${c.name}`, () => {
            const entries = c.entries_json === '' ? [] : (JSON.parse(c.entries_json) as ModelEntry[])
            const posture: unknown = c.posture_json === '' ? undefined : JSON.parse(c.posture_json)
            const challenge = c.challenge_hex === '' ? null : attestHexToBytes(c.challenge_hex)
            const halves = { keyBinding: new Uint8Array(32), auxBinding: attestHexToBytes(c.aux_hex) }
            let thrown: unknown
            try {
                verifyAux(halves, BigInt(c.node_id), entries, posture, c.echoed_nonce || undefined, challenge)
            } catch (err) {
                thrown = err
            }
            if (c.error === '') {
                expect(thrown).toBeUndefined()
            } else {
                expect(thrown, `verifyAux accepted what Go refused with ${c.error}`).toBeInstanceOf(AttestError)
                expect((thrown as AttestError).code).toBe(c.error)
            }
            expect(thrown === undefined ? '' : auxFailureTag(thrown)).toBe(c.tag)
        })
    }

    // TypeScript only: Go's challenge is a *[32]byte, so no vector can carry
    // a wrong-length one. A 31-byte challenge that happened to prefix the
    // echo must not pass.
    it('refuses a challenge that is not 32 bytes', () => {
        const echo = 'ab'.repeat(32)
        const halves = { keyBinding: new Uint8Array(32), auxBinding: new Uint8Array(32) }
        for (const len of [31, 33]) {
            const challenge = attestHexToBytes('ab'.repeat(len))
            expect(() => verifyAux(halves, 7n, [], undefined, echo, challenge)).toThrow(
                expect.objectContaining({ code: 'nonce_mismatch' }),
            )
        }
    })

    // TypeScript only: Go's AuxBinding is a [32]byte. A caller-built half
    // whose first 32 bytes match must not pass on the prefix.
    it('refuses an aux half that is not 32 bytes', () => {
        const entries: ModelEntry[] = [{ model_id: 'm', source: '', weights_digest: '', weights_state: 3 }]
        const good = auxBinding(7n, hApp(entries), NO_POSTURE, null)
        const long = new Uint8Array(33)
        long.set(good)
        const halves = { keyBinding: new Uint8Array(32), auxBinding: long }
        expect(() => verifyAux(halves, 7n, entries, undefined, undefined, null)).toThrow(
            expect.objectContaining({ code: 'aux_binding_mismatch' }),
        )
    })

    // The two mappings no vector reaches. The default is the fail-closed one:
    // an error nobody mapped must still refuse.
    it('maps an absent upper half and an unknown error', () => {
        expect(auxFailureTag(new AuxBindingAbsentError(new Uint8Array(32)))).toBe('aux_binding_absent')
        expect(auxFailureTag(new Error('some future error'))).toBe('aux_binding_mismatch')
    })

    // Go's HApp(nil) is the pending digest; a direct TS caller hashing an
    // absent bundle field must get the same, not malformed_model_entry.
    it('hashes null and undefined as the empty catalog', () => {
        expect(attestBytesToHex(hApp(null))).toBe(attestBytesToHex(hAppPending()))
        expect(attestBytesToHex(hApp(undefined))).toBe(attestBytesToHex(hAppPending()))
    })

    // BigInt(1.5) throws a bare RangeError; the verifier needs the coded one.
    it('refuses a fractional node id with unsafe_node_id', () => {
        expect(() => auxBinding(1.5, hAppPending(), NO_POSTURE, null)).toThrow(
            expect.objectContaining({ code: 'unsafe_node_id' }),
        )
    })

    // Every vector mismatch differs early; this pins the comparison to the
    // last byte.
    it('refuses an aux half that differs only in its last byte', () => {
        const entries: ModelEntry[] = [{ model_id: 'm', source: '', weights_digest: '', weights_state: 3 }]
        const good = auxBinding(7n, hApp(entries), NO_POSTURE, null)
        const halves = { keyBinding: new Uint8Array(32), auxBinding: flipBit(good, 31) }
        expect(() => verifyAux(halves, 7n, entries, undefined, undefined, null)).toThrow(
            expect.objectContaining({ code: 'aux_binding_mismatch' }),
        )
    })

    // The refusal carries the key half for the key-first check; it must be a
    // copy for the same reason the success path's halves are.
    it('carries a key half on AuxBindingAbsentError that does not alias the quote', () => {
        const q = Uint8Array.from(quote)
        expect(allZeroUpper(q)).toBe(true)
        let err: unknown
        try {
            splitReportData(q)
        } catch (e) {
            err = e
        }
        expect(err).toBeInstanceOf(AuxBindingAbsentError)
        const key = Uint8Array.from((err as AuxBindingAbsentError).keyBinding)
        q.fill(0)
        expect((err as AuxBindingAbsentError).keyBinding).toEqual(key)
    })

    // The nonce comes from parsed JSON. RegExp.test would stringify an array
    // holding 64 hex characters and pass it, and hexToBytes would then throw
    // a bare TypeError instead of a coded refusal.
    it('refuses a nonce that is not a string, and reads null as absent', () => {
        const entries: ModelEntry[] = [{ model_id: 'm', source: '', weights_digest: '', weights_state: 3 }]
        const challenge = new Uint8Array(32).fill(0x11)
        const hex = attestBytesToHex(challenge)
        const halves = { keyBinding: new Uint8Array(32), auxBinding: auxBinding(7n, hApp(entries), NO_POSTURE, challenge) }
        for (const echoed of [[hex], 5, { hex }]) {
            expect(() => verifyAux(halves, 7n, entries, undefined, echoed,null)).toThrow(
                expect.objectContaining({ code: 'malformed_nonce' }),
            )
            expect(() => verifyAux(halves, 7n, entries, undefined, echoed,challenge)).toThrow(
                expect.objectContaining({ code: 'nonce_mismatch' }),
            )
        }
        const unchallenged = { keyBinding: new Uint8Array(32), auxBinding: auxBinding(7n, hApp(entries), NO_POSTURE, null) }
        // null and '' are both absent, as Go's resolveNonce reads "".
        expect(() => verifyAux(unchallenged, 7n, entries, undefined, null, null)).not.toThrow()
        expect(() => verifyAux(unchallenged, 7n, entries, undefined,'', null)).not.toThrow()
    })

    it('parses a bundle body strictly', () => {
        const enc = new TextEncoder()
        expect(parseEvidenceBundle(enc.encode('{"nonce":"ab"}'))).toEqual({ nonce: 'ab' })
        // "x", then E2 82 (a truncated three-byte sequence), then "A".
        const bad = Uint8Array.from([...enc.encode('{"model_id":"x'), 0xe2, 0x82, ...enc.encode('A"}')])
        expect(() => parseEvidenceBundle(bad)).toThrow(TypeError)
        const bom = Uint8Array.from([0xef, 0xbb, 0xbf, ...enc.encode('{}')])
        expect(() => parseEvidenceBundle(bom)).toThrow(SyntaxError)
    })

    it('refuses a catalog that is not a list', () => {
        expect(() => hApp({} as unknown as ModelEntry[])).toThrow(
            expect.objectContaining({ code: 'malformed_model_entry' }),
        )
    })

    // The halves must be copies: a caller that reuses or zeroes its quote
    // buffer must not change them under a later comparison.
    it('returns halves that do not alias the quote', () => {
        const q = withAuxHalf(quote, new Uint8Array(32).fill(0x5a))
        const halves = splitReportData(q)
        const key = Uint8Array.from(halves.keyBinding)
        q.fill(0)
        expect(halves.auxBinding).toEqual(new Uint8Array(32).fill(0x5a))
        expect(halves.keyBinding).toEqual(key)
    })
})

describe('h_posture vectors', () => {
    it('has cases', () => {
        expect(vectors.h_posture.length).toBeGreaterThan(5)
    })

    for (const c of vectors.h_posture) {
        it(`hashes the posture identically to Go: ${c.name}`, () => {
            const posture: unknown = c.posture_json === '' ? undefined : JSON.parse(c.posture_json)
            expect(attestBytesToHex(hPosture(posture))).toBe(c.expected_hex)
        })
    }

    // Go's decoder refuses a wrongly typed posture with the whole bundle, so
    // no vector can carry one; these hold the TypeScript refusal in place.
    it('refuses a posture that is not an object, or whose fields have the wrong type', () => {
        for (const bad of ['in_enclave', 5, [], { plaintext_terminates: 1 }, { upstream_base_url: {} }, { zero_retention: 'true' }]) {
            expect(() => hPosture(bad), JSON.stringify(bad)).toThrow(
                expect.objectContaining({ code: 'malformed_posture' }),
            )
        }
        expect(auxFailureTag(new AttestError('malformed_posture', 'x'))).toBe('posture_preimage_invalid')
    })
})

describe('aux_binding vectors', () => {
    it('covers an id past 2^53, which is why node_id rides as a string', () => {
        expect(vectors.aux_binding.length).toBeGreaterThan(0)
        expect(
            vectors.aux_binding.some((c) => BigInt(c.node_id) > BigInt(Number.MAX_SAFE_INTEGER)),
        ).toBe(true)
    })

    for (const c of vectors.aux_binding) {
        it(`computes the aux binding identically to Go: ${c.name}`, () => {
            const nonce = c.nonce_hex === '' ? null : attestHexToBytes(c.nonce_hex)
            const hp = attestHexToBytes(c.h_posture_hex)
            const got = auxBinding(BigInt(c.node_id), attestHexToBytes(c.h_app_hex), hp, nonce)
            expect(attestBytesToHex(got)).toBe(c.expected_hex)

            // The signature takes bigint | number, and every line above this
            // one passes a bigint — so without this, the number path has no
            // successful-path coverage at all and could encode a different id
            // with the suite still green. A browser caller holding a small
            // node_id from JSON takes exactly that path.
            if (BigInt(c.node_id) <= BigInt(Number.MAX_SAFE_INTEGER)) {
                const asNumber = auxBinding(Number(c.node_id), attestHexToBytes(c.h_app_hex), hp, nonce)
                expect(attestBytesToHex(asNumber)).toBe(c.expected_hex)
            }
        })
    }

    // Moves one input at a time away from a binding that verifies. Mirrors
    // Go's TestVerifyAuxIsTheGate.
    it('verifyAux is the gate, and moving any single input closes it', () => {
        const entries: ModelEntry[] = [
            { model_id: 'm', source: 'hf/m', weights_digest: 'sha256:ab12', weights_state: 1 },
        ]
        const nonce = new Uint8Array(32)
        nonce[0] = 1
        const nonceHex = attestBytesToHex(nonce)
        const halves = { keyBinding: new Uint8Array(32), auxBinding: auxBinding(7n, hApp(entries), NO_POSTURE, nonce) }

        expect(() => verifyAux(halves, 7n, entries, undefined, nonceHex, nonce)).not.toThrow()

        const other: ModelEntry[] = [
            { model_id: 'm', source: 'hf/m', weights_digest: 'sha256:ff99', weights_state: 1 },
        ]
        const otherNonce = new Uint8Array(32)
        otherNonce[31] = 9
        const cases: [string, bigint, ModelEntry[], string, string][] = [
            ['a different node id', 8n, entries, nonceHex, 'aux_binding_mismatch'],
            ['a substituted weights digest', 7n, other, nonceHex, 'aux_binding_mismatch'],
            ['a different echoed nonce', 7n, entries, attestBytesToHex(otherNonce), 'nonce_mismatch'],
            ['the echo dropped', 7n, entries, '', 'nonce_mismatch'],
            ['the catalog dropped', 7n, [], nonceHex, 'happ_preimage_missing'],
            ['a duplicate model id', 7n, [entries[0]!, entries[0]!], nonceHex, 'duplicate_model_id'],
        ]
        for (const [name, id, e, echoed, code] of cases) {
            let thrown: unknown
            try {
                verifyAux(halves, id, e, undefined, echoed, nonce)
            } catch (err) {
                thrown = err
            }
            expect(thrown, `verifyAux accepted ${name}`).toBeInstanceOf(AttestError)
            expect((thrown as AttestError).code, name).toBe(code)
        }
    })

    it('treats an absent nonce and an all-zero nonce as one preimage', () => {
        const h = hAppPending()
        expect(attestBytesToHex(auxBinding(7n, h, NO_POSTURE, null))).toBe(
            attestBytesToHex(auxBinding(7n, h, NO_POSTURE, new Uint8Array(32))),
        )
    })

    it('refuses a node id that arrived as an imprecise number', () => {
        expect(() => auxBinding(Number.MAX_SAFE_INTEGER + 2, hAppPending(), NO_POSTURE, null)).toThrow(AttestError)
        try {
            auxBinding(Number.MAX_SAFE_INTEGER + 2, hAppPending(), NO_POSTURE, null)
        } catch (err) {
            expect((err as AttestError).code).toBe('unsafe_node_id')
        }
    })

    // Go cannot reach either condition ([32]byte / *[32]byte make them
    // unrepresentable), so no golden vector pins them and these are the only
    // thing holding the code spelling in place.
    it('refuses a wrong-width nonce or H_app rather than padding it', () => {
        for (const bad of [new Uint8Array(16), new Uint8Array(33), new Uint8Array(0)]) {
            try {
                auxBinding(7n, hAppPending(), NO_POSTURE, bad)
                throw new Error(`auxBinding accepted a ${bad.length}-byte nonce`)
            } catch (err) {
                expect(err).toBeInstanceOf(AttestError)
                expect((err as AttestError).code).toBe('invalid_aux_input')
            }
        }
        // Both sides of 32, not just below it: a `< 32` guard accepts a
        // 33- or 64-byte H_app and concatenates it whole, producing a
        // binding over a preimage no Go implementation can reproduce —
        // a silent divergence rather than the refusal this is for.
        for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(64)]) {
            try {
                auxBinding(7n, bad, NO_POSTURE, null)
                throw new Error(`auxBinding accepted a ${bad.length}-byte H_app`)
            } catch (err) {
                expect(err).toBeInstanceOf(AttestError)
                expect((err as AttestError).code).toBe('invalid_aux_input')
            }
        }
        for (const bad of [new Uint8Array(31), new Uint8Array(33)]) {
            try {
                auxBinding(7n, hAppPending(), bad, null)
                throw new Error(`auxBinding accepted a ${bad.length}-byte H_posture`)
            } catch (err) {
                expect(err).toBeInstanceOf(AttestError)
                expect((err as AttestError).code).toBe('invalid_aux_input')
            }
        }
    })

    // Twin of Go's "app_models and posture both bad" case: H_app is checked
    // first, so the tag names the catalog in both languages.
    it('reports a bad catalog before a bad posture', () => {
        const halves = { keyBinding: new Uint8Array(32), auxBinding: new Uint8Array(32).fill(1) }
        try {
            // A parsed bundle can carry any JSON here; the type is a promise
            // verifyAux itself does not rely on.
            verifyAux(halves, 7n, 'x' as unknown as ModelEntry[], [], null, null)
            throw new Error('verifyAux accepted a bad catalog and posture')
        } catch (err) {
            expect(err).toBeInstanceOf(AttestError)
            expect(auxFailureTag(err)).toBe('happ_preimage_invalid')
        }
    })

    // Go's uint64 cannot express a negative id, so no golden vector can ever
    // pin this and the TS guard is load-bearing on its own. Without it the
    // value reaches the mask, and BigInt(-1) & 0xffff…n is 2^64-1 — so node
    // -1 would mint the EXACT binding of the largest valid node id rather
    // than an error, a silent collision in the one field whose job is to
    // stop an operator's own siblings from lifting each other's quotes.
    it('refuses a negative node id rather than wrapping it to 2^64-1', () => {
        for (const bad of [-1, -1n, Number.MIN_SAFE_INTEGER]) {
            try {
                auxBinding(bad, hAppPending(), NO_POSTURE, null)
                throw new Error(`auxBinding accepted node id ${bad}`)
            } catch (err) {
                expect(err).toBeInstanceOf(AttestError)
                expect((err as AttestError).code).toBe('unsafe_node_id')
            }
        }
    })
})

describe('attest failure modes', () => {
    const events = parseEventLog(rawLog)

    it('refuses a log that extends nothing', () => {
        // An empty replay is 48 zero bytes, which compares EQUAL to an
        // unmeasured register. Both halves of that pair have to refuse.
        expect(() => replayRTMR3([])).toThrowError(
            expect.objectContaining({ code: 'empty_replay' }) as unknown as Error,
        )
        const nonRuntime: DstackEvent[] = [
            { imr: 3, event_type: 1, digest: '', event: 'x', event_payload: 'aa' },
        ]
        expect(() => replayRTMR3(nonRuntime)).toThrowError(
            expect.objectContaining({ code: 'empty_replay' }) as unknown as Error,
        )
    })

    it('refuses an undecodable payload rather than skipping it', () => {
        const bad = events.map((e) =>
            e.event_type === DSTACK_RUNTIME_EVENT_TYPE ? { ...e, event_payload: 'zz' } : e,
        )
        expect(() => replayRTMR3(bad)).toThrowError(
            expect.objectContaining({ code: 'undecodable_payload' }) as unknown as Error,
        )
    })

    it('refuses an all-zero RTMR3 in the quote', () => {
        const zeroed = Uint8Array.from(quote)
        zeroed.fill(0, 48 + 328 + 3 * 48, 48 + 328 + 4 * 48)
        expect(() => verifyEventLog(rawLog, zeroed)).toThrowError(
            expect.objectContaining({ code: 'zero_rtmr' }) as unknown as Error,
        )
    })

    it('refuses a quote too short to hold RTMR3 instead of returning measurements', () => {
        // This branch fails OPEN under one plausible edit: returning the
        // measurements anyway hands a caller a compose-hash that was
        // compared against nothing.
        expect(() => verifyEventLog(rawLog, quote.subarray(0, 100))).toThrowError(
            expect.objectContaining({ code: 'short_quote' }) as unknown as Error,
        )
    })

    it('reports a genuine replay mismatch', () => {
        expect(() => verifyEventLog(rawLog, flipBit(quote, 48 + 328 + 3 * 48))).toThrowError(
            expect.objectContaining({ code: 'rtmr3_mismatch' }) as unknown as Error,
        )
    })

    it('does not read the log’s own digest field', () => {
        // dstack leaves `digest` empty on every runtime event, so an
        // implementation that trusted it would extend with nothing.
        // Filling it with garbage must change nothing at all.
        const withDigests = events.map((e) => ({ ...e, digest: 'de'.repeat(48) }))
        expect(attestBytesToHex(replayRTMR3(withDigests).value)).toBe(vectors.replay.rtmr3_hex)
    })

    it('filters on event_type, not imr', () => {
        // In the real capture the two predicates happen to select the
        // same set, so no fixture-based assertion can tell them apart.
        // These are chosen so they disagree.
        const synthetic: DstackEvent[] = [
            { imr: 3, event_type: 4, digest: '', event: 'boot-ish', event_payload: 'aa' },
            { imr: 1, event_type: DSTACK_RUNTIME_EVENT_TYPE, digest: '', event: 'runtime', event_payload: 'bb' },
        ]
        expect(replayRTMR3(synthetic).extends).toBe(1)
        expect(runtimeMeasurements(synthetic)).toEqual({ runtime: 'bb' })
    })

    it('keeps the first occurrence of a duplicated event name', () => {
        // An appended event must not be able to displace a measured one.
        const dup: DstackEvent[] = [
            { imr: 3, event_type: DSTACK_RUNTIME_EVENT_TYPE, digest: '', event: 'compose-hash', event_payload: 'AA' },
            { imr: 3, event_type: DSTACK_RUNTIME_EVENT_TYPE, digest: '', event: 'compose-hash', event_payload: 'bb' },
        ]
        expect(runtimeMeasurements(dup)).toEqual({ 'compose-hash': 'aa' })
    })

    it('rejects a malformed log', () => {
        expect(() => parseEventLog('not json')).toThrowError(AttestError)
        expect(() => parseEventLog('{"imr":3}')).toThrowError(
            expect.objectContaining({ code: 'malformed_log' }) as unknown as Error,
        )
    })

    it('returns null rather than a short read on truncated quotes', () => {
        const short = quote.subarray(0, 60)
        expect(quoteRTMR(short, 3)).toBeNull()
        expect(quoteMRTD(short)).toBeNull()
        expect(quoteReportData(short)).toBeNull()
        expect(() => splitReportData(short)).toThrowError(
            expect.objectContaining({ code: 'report_data_absent' }) as unknown as Error,
        )
        expect(quoteRTMR(quote, 4)).toBeNull()
        expect(quoteRTMR(quote, -1)).toBeNull()
        expect(quoteTEEType(new Uint8Array(2))).toBeNull()
    })

    // Each accessor's guard is `length < offset + width`, and the test
    // above uses lengths nowhere near any of those boundaries — so a
    // guard could lose its width term entirely and still pass. One of
    // those is a fail-open rather than a short read: drop the width from
    // quoteReportData and a 552-byte quote yields a 32-byte field whose
    // "padding" is the empty slice, allZero([]) is true, and
    // splitReportData hands back a binding hash from a quote that
    // contains no padding at all — defeating the loop above.
    //
    // One byte either side of each real boundary is the only assertion
    // that pins the arithmetic instead of the existence of a check.
    it.each([
        { name: 'quoteRTMR(3)', end: 48 + 328 + 3 * 48 + 48, f: (q: Uint8Array) => quoteRTMR(q, 3) },
        { name: 'quoteRTMR(0)', end: 48 + 328 + 48, f: (q: Uint8Array) => quoteRTMR(q, 0) },
        { name: 'quoteMRTD', end: 48 + 136 + 48, f: quoteMRTD },
        { name: 'quoteReportData', end: 48 + 520 + 64, f: quoteReportData },
        { name: 'quoteTEEType', end: 4 + 4, f: quoteTEEType },
    ])('$name reads exactly at its boundary and not one byte before', ({ end, f }) => {
        expect(f(quote.subarray(0, end - 1))).toBeNull()
        expect(f(quote.subarray(0, end))).not.toBeNull()
    })

    // splitReportData gets its own boundary assertion because it throws
    // rather than returning null, and because its two refusals make a
    // sharper test than the table above could: one byte short the field
    // is unreadable, and at exactly the boundary it is readable and the
    // complaint MOVES to the upper half. A guard that lost its width
    // term would report aux_binding_absent on both sides.
    it('splitReportData reads exactly at its boundary, and its refusal changes there', () => {
        const end = 48 + 520 + 64
        expect(() => splitReportData(quote.subarray(0, end - 1))).toThrowError(
            expect.objectContaining({ code: 'report_data_absent' }) as unknown as Error,
        )
        expect(() => splitReportData(quote.subarray(0, end))).toThrowError(
            expect.objectContaining({ code: 'aux_binding_absent' }) as unknown as Error,
        )
    })
})

// Parity against logs an OPERATOR wrote, rather than the one
// well-formed capture. Go is the reference; every expectation here is
// recorded from it.
//
// This block exists because a mutation pass found a live divergence in
// the gap it covers: TypeScript stripped a `0X` payload prefix that Go
// does not, so identical operator-authored evidence decoded in the
// browser and failed in the node — two relying parties reaching
// opposite verdicts, which is precisely what the shared module exists
// to prevent. Real dstack emits no prefix, which is what let it ship.
//
// The passing cases matter as much as the failing ones: leniency added
// to EITHER implementation now turns both suites red.
describe('attest hostile logs', () => {
    it('has cases', () => {
        expect(vectors.hostile.length).toBeGreaterThan(0)
        // The divergence case specifically — if it is ever dropped from
        // the generator, this block silently stops testing the thing it
        // was written for.
        expect(vectors.hostile.some((c) => c.name.includes('0X'))).toBe(true)
        expect(vectors.hostile.some((c) => c.replay_error !== '')).toBe(true)
        expect(vectors.hostile.some((c) => c.replay_error === '')).toBe(true)
    })

    for (const c of vectors.hostile) {
        it(`replays like Go: ${c.name}`, () => {
            const events = parseEventLog(c.log)

            if (c.replay_error !== '') {
                let code: string | undefined
                try {
                    replayRTMR3(events)
                } catch (e) {
                    code = (e as AttestError).code
                }
                expect(code, c.why).toBe(c.replay_error)
            } else {
                const { value, extends: n } = replayRTMR3(events)
                expect(n, c.why).toBe(c.extends)
                expect(attestBytesToHex(value), c.why).toBe(c.rtmr3_hex)
            }

            // Pinned on every case, including the ones whose replay
            // fails: runtimeMeasurements is separately exported, and a
            // caller reading it without replaying is the mistake this
            // package is arranged against.
            expect(runtimeMeasurements(events), c.why).toEqual(c.measurements)
        })
    }
})
