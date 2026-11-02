/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The freshness floor on node-carried collateral. Mirrors
// CollateralFreshEnough in proto/go/attest/collateral.go, whose godoc carries
// the reasoning: Intel's signature proves a document's contents and says
// nothing about which validly signed vintage the node chose to hand over, so a
// verifier that falls back to carried collateral bounds how old each document
// may be.
//
// Pinned against Go by proto/testdata/collateral_vectors.json, down to how a
// date is read: an issueDate Go cannot parse, or a CRL thisUpdate it refuses,
// is not fresh, so a reader that dated more than Go does would accept a set
// Go falls back from.
//
// One part is not mirrored. Go dates a CRL with x509.ParseRevocationList,
// which also parses the algorithm identifier's contents, the issuer name and
// everything after nextUpdate. This reads the CRL's structure up to
// nextUpdate with the same DER rules and stops there, so it dates some CRLs
// Go refuses. None of those is one Intel signed, and the verifier that
// consumes the set refuses it; the two differ only in which failure a payer
// sees.

import { collateralComplete, type TEECollateral } from '../inject/tee.js'
import { epochNanosFromMillis, parseRFC3339 } from '../inject/rfc3339.js'
import { withinGoNestingDepth } from '../inject/json-depth.js'
import { goTrimSpace } from '../inject/gostrings.js'

/**
 * How stale node-carried collateral may be before a verifier refuses to fall
 * back to it. Mirrors EmbeddedCollateralMaxAge (14 days), deliberately tighter
 * than Intel's own ~30-day nextUpdate. The root CA CRL is not held to it; see
 * collateralFreshEnough.
 */
export const EMBEDDED_COLLATERAL_MAX_AGE_MS = 14 * 24 * 60 * 60 * 1000

/**
 * The oldest root CA CRL a verifier accepts from a node's carried set: the
 * thisUpdate of the newest one Intel has published that this module knows of.
 * Mirrors Go's MinRootCACRLThisUpdate, whose godoc says what an older one would
 * hide and when to bump it.
 */
export const MIN_ROOT_CA_CRL_THIS_UPDATE_MS = Date.UTC(2026, 1, 26, 13, 4, 0)

/**
 * collateralFreshEnough reports whether every document in the set is recent
 * enough to fall back to. Mirrors Go's CollateralFreshEnough.
 *
 * Fail-closed: an incomplete set, or an unparseable or undated document, is not
 * fresh. Every document is dated, because a node can pair fresh TCB info with
 * an older CRL that predates the revocation of its own PCK certificate. A
 * document dated after nowMs is refused too: now minus a future instant is
 * negative and would otherwise pass any floor.
 *
 * TCB info, QE identity and the PCK CRL must be no older than maxAgeMs. The
 * root CA CRL cannot be: Intel reissues it about once a year, so any shorter
 * floor refuses every honest set. It must instead be no older than
 * MIN_ROOT_CA_CRL_THIS_UPDATE_MS and inside its own window,
 * thisUpdate <= now <= nextUpdate, and is refused without a nextUpdate.
 */
export function collateralFreshEnough(
    c: TEECollateral | null | undefined,
    nowMs: number,
    maxAgeMs: number,
): boolean {
    if (!collateralComplete(c)) return false
    const now = epochNanosFromMillis(nowMs)
    const maxAge = epochNanosFromMillis(maxAgeMs)
    const dates = [
        () => collateralIssuedAt(c.tcb_info, 'tcbInfo'),
        () => collateralIssuedAt(c.qe_identity, 'enclaveIdentity'),
        () => crlThisUpdate(c.pck_crl),
    ]
    for (const at of dates) {
        const t = at()
        if (t === null || t > now || now - t > maxAge) return false
    }
    const root = crlWindow(c.root_ca_crl)
    if (root === null || root.nextUpdate === null) return false
    if (root.thisUpdate < epochNanosFromMillis(MIN_ROOT_CA_CRL_THIS_UPDATE_MS)) return false
    return root.thisUpdate <= now && now <= root.nextUpdate
}

/**
 * collateralIssuedAt reads issueDate off a signed collateral document, as
 * nanoseconds since the epoch, or null. Mirrors Go's issuedAt: the document
 * must be the bare inner object, and one still wrapped in `wrapper` is refused
 * rather than unwrapped, because the verifier would then rebuild a
 * double-wrapped envelope that verifies nowhere.
 */
export function collateralIssuedAt(doc: string, wrapper: string): bigint | null {
    if (!withinGoNestingDepth(doc)) return null
    let parsed: unknown
    try {
        parsed = JSON.parse(doc)
    } catch {
        return null
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null
    if (Object.prototype.hasOwnProperty.call(parsed, wrapper)) return null
    if (!Object.prototype.hasOwnProperty.call(parsed, 'issueDate')) return null
    const raw = (parsed as Record<string, unknown>)['issueDate']
    return typeof raw === 'string' ? parseRFC3339(raw) : null
}

/**
 * crlThisUpdate reads thisUpdate off a hex-encoded DER CRL, as nanoseconds
 * since the epoch, or null. Mirrors Go's crlThisUpdate; see the file header
 * for what it does not read.
 */
export function crlThisUpdate(hexDER: string): bigint | null {
    return crlWindow(hexDER)?.thisUpdate ?? null
}

/**
 * crlNextUpdate reads nextUpdate off a hex-encoded DER CRL, or null when the
 * CRL cannot be dated or carries none. An explicit Go zero time reads as none,
 * because Go cannot tell it from an absent one.
 */
export function crlNextUpdate(hexDER: string): bigint | null {
    return crlWindow(hexDER)?.nextUpdate ?? null
}

function crlWindow(hexDER: string): { thisUpdate: bigint; nextUpdate: bigint | null } | null {
    const der = hexDecode(goTrimSpace(hexDER))
    if (der === null || der.length === 0) return null

    // CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }
    const outer = readElement(der, 0, der.length, TAG_SEQUENCE)
    if (outer === null) return null
    const tbs = readElement(der, outer.start, outer.end, TAG_SEQUENCE)
    if (tbs === null) return null
    const outerAlg = readElement(der, tbs.next, outer.end, TAG_SEQUENCE)
    if (outerAlg === null) return null
    const sig = readElement(der, outerAlg.next, outer.end, TAG_BIT_STRING)
    if (sig === null || !validBitString(der.subarray(sig.start, sig.end))) return null

    // TBSCertList ::= SEQUENCE { version INTEGER (v2 only, as Go requires),
    //   signature AlgorithmIdentifier, issuer Name, thisUpdate Time, … }
    const version = readElement(der, tbs.start, tbs.end, TAG_INTEGER)
    if (version === null || version.end - version.start !== 1 || der[version.start] !== 1) return null
    const alg = readElement(der, version.next, tbs.end, TAG_SEQUENCE)
    if (alg === null) return null
    if (!bytesEqual(der.subarray(alg.start, alg.end), der.subarray(outerAlg.start, outerAlg.end))) {
        return null
    }
    const issuer = readElement(der, alg.next, tbs.end, TAG_SEQUENCE)
    if (issuer === null) return null
    const thisUpdate = readElement(der, issuer.next, tbs.end)
    if (thisUpdate === null) return null
    const t = derTime(der, thisUpdate)
    // Go refuses the zero time.Time, 0001-01-01T00:00:00Z, as undated.
    if (t === null || t === GO_ZERO_TIME) return null

    // nextUpdate Time OPTIONAL. Go reads it whenever the next tag is a time,
    // and refuses the whole CRL when that read fails.
    const tag = thisUpdate.next < tbs.end ? der[thisUpdate.next] : undefined
    if (tag !== TAG_UTC_TIME && tag !== TAG_GENERALIZED_TIME) return { thisUpdate: t, nextUpdate: null }
    const nextUpdate = readElement(der, thisUpdate.next, tbs.end)
    if (nextUpdate === null) return null
    const n = derTime(der, nextUpdate)
    if (n === null) return null
    return { thisUpdate: t, nextUpdate: n === GO_ZERO_TIME ? null : n }
}

function derTime(der: Uint8Array, el: Element): bigint | null {
    const text = latin1(der.subarray(el.start, el.end))
    if (el.tag === TAG_UTC_TIME) return utcTime(text)
    if (el.tag === TAG_GENERALIZED_TIME) return generalizedTime(text)
    return null
}

const TAG_INTEGER = 0x02
const TAG_BIT_STRING = 0x03
const TAG_SEQUENCE = 0x30
const TAG_UTC_TIME = 0x17
const TAG_GENERALIZED_TIME = 0x18

const GO_ZERO_TIME = -62135596800n * 1_000_000_000n

interface Element {
    tag: number
    /** The value's bounds. */
    start: number
    end: number
    /** Where the next sibling starts. */
    next: number
}

// One DER element within [off, limit), as cryptobyte reads it: a low tag
// number only, and a minimal length encoding of at most four octets.
function readElement(b: Uint8Array, off: number, limit: number, want?: number): Element | null {
    if (limit - off < 2) return null
    const tag = b[off]!
    if ((tag & 0x1f) === 0x1f) return null
    const lenByte = b[off + 1]!
    let len: number
    let start: number
    if ((lenByte & 0x80) === 0) {
        len = lenByte
        start = off + 2
    } else {
        const n = lenByte & 0x7f
        if (n === 0 || n > 4 || limit - off < 2 + n) return null
        len = 0
        for (let i = 0; i < n; i++) len = len * 256 + b[off + 2 + i]!
        if (len < 128) return null // should have been the short form
        if (b[off + 2] === 0) return null // a leading zero octet
        start = off + 2 + n
    }
    const end = start + len
    if (end > limit) return null
    if (want !== undefined && tag !== want) return null
    return { tag, start, end, next: end }
}

// cryptobyte's ReadASN1BitString: a padding count of at most 7, none on an
// empty string, and the padding bits themselves zero.
function validBitString(v: Uint8Array): boolean {
    if (v.length === 0) return false
    const pad = v[0]!
    if (pad > 7) return false
    if (v.length === 1) return pad === 0
    return (v[v.length - 1]! & ((1 << pad) - 1)) === 0
}

// UTCTime as cryptobyte accepts it: Go's "060102150405Z0700", or without the
// seconds, and only in the form Go would write back. Years 50-99 are 19xx.
// Go subtracts that century in the parsed zone, which can be the host's Local
// zone when the offsets coincide, so a 1950s date with an offset can land a
// little differently in Go; any such date is decades stale either way, and the
// vectors leave it out.
const UTC_TIME_RE = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})$/

function utcTime(s: string): bigint | null {
    const m = UTC_TIME_RE.exec(s)
    if (!m) return null
    const yy = Number(m[1])
    return civilNanos(yy < 50 ? 2000 + yy : 1900 + yy, m[2]!, m[3]!, m[4]!, m[5]!, m[6] ?? '00', m[7]!)
}

// GeneralizedTime as cryptobyte accepts it: "20060102150405Z0700" written back
// unchanged, so no fraction and no minute-only form.
const GENERALIZED_TIME_RE = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(Z|[+-]\d{4})$/

function generalizedTime(s: string): bigint | null {
    const m = GENERALIZED_TIME_RE.exec(s)
    if (!m) return null
    return civilNanos(Number(m[1]), m[2]!, m[3]!, m[4]!, m[5]!, m[6]!, m[7]!)
}

// Assembles a DER time through parseRFC3339, which already holds Go's calendar
// rules. The zone must be one Go writes back as it was read: "Z" for UTC (so
// +0000 and -0000 are refused) and at most 59 minutes.
function civilNanos(
    year: number,
    mo: string,
    d: string,
    h: string,
    mi: string,
    sec: string,
    zone: string,
): bigint | null {
    let z = 'Z'
    if (zone !== 'Z') {
        const oh = Number(zone.slice(1, 3))
        const om = Number(zone.slice(3, 5))
        if (oh > 24 || om > 59 || (oh === 0 && om === 0)) return null
        z = `${zone[0]}${zone.slice(1, 3)}:${zone.slice(3, 5)}`
    }
    const y = String(year).padStart(4, '0')
    return parseRFC3339(`${y}-${mo}-${d}T${h}:${mi}:${sec}${z}`)
}

function hexDecode(s: string): Uint8Array | null {
    if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) return null
    const out = new Uint8Array(s.length / 2)
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16)
    return out
}

function latin1(b: Uint8Array): string {
    let s = ''
    for (const c of b) s += String.fromCharCode(c)
    return s
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
    return true
}
