/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Go's mime.ParseMediaType and mime/multipart reader, as far as the payer's
// image-edit parse uses them, so a body both SDKs read gives the same model,
// count and stream flag. Text is held as binary strings, one char per byte,
// because Go's strings are bytes: a boundary or a header can carry any byte.
//
// The reader emulates Go's stack call for call rather than reading the whole
// body at once: bufio.Reader's 4096-byte buffer, multipart's part reader,
// textproto's header reader and quotedprintable's reader with its own buffer.
// Where Go resumes after a part it skipped, and which lines are too long,
// depend on those buffers, so a shortcut over the whole body reads some bodies
// differently.

import { goDecodeUTF8, goQuote } from './gotext.js'

/** binaryOf is bytes as a binary string. */
export function binaryOf(b: Uint8Array): string {
    let out = ''
    for (let i = 0; i < b.length; i += 0x8000) {
        out += String.fromCharCode(...b.subarray(i, i + 0x8000))
    }
    return out
}

/** utf8Binary is s's UTF-8 encoding as a binary string. */
export function utf8Binary(s: string): string {
    return binaryOf(new TextEncoder().encode(s))
}

/** textOf is a binary string as Go's string(b) reads: each invalid byte a U+FFFD. */
export function textOf(s: string): string {
    return goDecodeUTF8(s)
}

// ---- mime.ParseMediaType ----

// The multi-byte UTF-8 encodings of the runes unicode.IsSpace accepts.
const WIDE_SPACES = [
    '\xc2\x85',
    '\xc2\xa0',
    '\xe1\x9a\x80',
    ...Array.from({ length: 11 }, (_, i) => '\xe2\x80' + String.fromCharCode(0x80 + i)),
    '\xe2\x80\xa8',
    '\xe2\x80\xa9',
    '\xe2\x80\xaf',
    '\xe2\x81\x9f',
    '\xe3\x80\x80',
]

function asciiSpace(c: number): boolean {
    return c === 0x20 || (c >= 0x09 && c <= 0x0d)
}

function spaceAt(s: string, i: number): number {
    if (i >= s.length) return 0
    if (asciiSpace(s.charCodeAt(i))) return 1
    for (const w of WIDE_SPACES) if (s.startsWith(w, i)) return w.length
    return 0
}

function spaceBefore(s: string): number {
    if (s.length === 0) return 0
    if (asciiSpace(s.charCodeAt(s.length - 1))) return 1
    for (const w of WIDE_SPACES) if (s.endsWith(w)) return w.length
    return 0
}

function trimLeftSpace(s: string): string {
    let i = 0
    for (let n = spaceAt(s, 0); n > 0; n = spaceAt(s, i)) i += n
    return s.slice(i)
}

function trimSpace(s: string): string {
    s = trimLeftSpace(s)
    for (let n = spaceBefore(s); n > 0; n = spaceBefore(s)) s = s.slice(0, s.length - n)
    return s
}

// toLower is strings.ToLower where it matters: only ASCII letters, the dotted
// capital I and the Kelvin sign lower to ASCII, and anything else non-ASCII
// fails the token check whatever it lowers to.
function toLower(s: string): string {
    let out = ''
    for (let i = 0; i < s.length; ) {
        if (s.startsWith('\xc4\xb0', i)) {
            out += 'i'
            i += 2
        } else if (s.startsWith('\xe2\x84\xaa', i)) {
            out += 'k'
            i += 3
        } else {
            const c = s.charCodeAt(i)
            out += c >= 0x41 && c <= 0x5a ? String.fromCharCode(c + 32) : s[i]
            i++
        }
    }
    return out
}

function isTokenChar(c: number): boolean {
    return c < 0x80 && /[!#$%&'*+\-.^_`{|}~0-9A-Za-z]/.test(String.fromCharCode(c))
}

function isTSpecial(c: number): boolean {
    return c < 0x80 && '()<>@,;:\\"/[]?='.includes(String.fromCharCode(c))
}

function consumeToken(v: string): [string, string] {
    let i = 0
    while (i < v.length && isTokenChar(v.charCodeAt(i))) i++
    return [v.slice(0, i), v.slice(i)]
}

function consumeValue(v: string): [string, string] {
    if (v === '') return ['', '']
    if (v[0] !== '"') return consumeToken(v)
    let buf = ''
    for (let i = 1; i < v.length; i++) {
        const r = v[i]
        if (r === '"') return [buf, v.slice(i + 1)]
        if (r === '\\' && i + 1 < v.length && isTSpecial(v.charCodeAt(i + 1))) {
            buf += v[i + 1]
            i++
            continue
        }
        if (r === '\r' || r === '\n') return ['', v]
        buf += r
    }
    return ['', v]
}

function consumeMediaParam(v: string): [string, string, string] {
    let rest = trimLeftSpace(v)
    if (!rest.startsWith(';')) return ['', '', v]
    rest = trimLeftSpace(rest.slice(1))
    let param: string
    ;[param, rest] = consumeToken(rest)
    param = toLower(param)
    if (param === '') return ['', '', v]
    rest = trimLeftSpace(rest)
    if (!rest.startsWith('=')) return ['', '', v]
    rest = trimLeftSpace(rest.slice(1))
    const [value, rest2] = consumeValue(rest)
    if (value === '' && rest2 === rest) return ['', '', v]
    return [param, value, rest2]
}

function checkMediaTypeDisposition(s: string): void {
    const [typ, rest] = consumeToken(s)
    if (typ === '') throw new Error('mime: no media type')
    if (rest === '') return
    if (!rest.startsWith('/')) throw new Error('mime: expected slash after first token')
    const [subtype, rest2] = consumeToken(rest.slice(1))
    if (subtype === '') throw new Error('mime: expected token after slash')
    if (rest2 !== '') throw new Error('mime: unexpected content after media subtype')
}

function isHex(c: string | undefined): boolean {
    return c !== undefined && /^[0-9a-fA-F]$/.test(c)
}

function percentHexUnescape(s: string): [string, boolean] {
    let out = ''
    for (let i = 0; i < s.length; ) {
        if (s[i] !== '%') {
            out += s[i]
            i++
            continue
        }
        if (i + 2 >= s.length || !isHex(s[i + 1]) || !isHex(s[i + 2])) return ['', false]
        out += String.fromCharCode(parseInt(s.slice(i + 1, i + 3), 16))
        i += 3
    }
    return [out, true]
}

function decode2231Enc(v: string): string | null {
    const q = v.indexOf("'")
    if (q < 0) return null
    const rest = v.slice(q + 1)
    const q2 = rest.indexOf("'")
    if (q2 < 0) return null
    const charset = toLower(v.slice(0, q))
    if (charset !== 'us-ascii' && charset !== 'utf-8') return null
    const [out, ok] = percentHexUnescape(rest.slice(q2 + 1))
    return ok ? out : null
}

/** A parsed media type: the lowered type and its parameters, all as binary strings. */
export interface MediaType {
    mediatype: string
    params: Map<string, string>
}

/** parseMediaType is Go's mime.ParseMediaType over a binary string; it throws Go's errors. */
export function parseMediaType(v: string): MediaType {
    const semi = v.indexOf(';')
    const base = semi < 0 ? v : v.slice(0, semi)
    const mediatype = trimSpace(toLower(base))
    checkMediaTypeDisposition(mediatype)

    const params = new Map<string, string>()
    let continuation: Map<string, Map<string, string>> | undefined
    v = v.slice(base.length)
    while (v.length > 0) {
        v = trimLeftSpace(v)
        if (v.length === 0) break
        const [key, value, rest] = consumeMediaParam(v)
        if (key === '') {
            if (trimSpace(rest) === ';') break
            throw new Error('mime: invalid media parameter')
        }
        let pmap = params
        const star = key.indexOf('*')
        if (star >= 0) {
            continuation ??= new Map()
            const baseName = key.slice(0, star)
            let m = continuation.get(baseName)
            if (m === undefined) {
                m = new Map()
                continuation.set(baseName, m)
            }
            pmap = m
        }
        const prev = pmap.get(key)
        if (prev !== undefined && prev !== value) throw new Error('mime: duplicate parameter name')
        pmap.set(key, value)
        v = rest
    }

    for (const [key, pieces] of continuation ?? []) {
        const single = pieces.get(key + '*')
        if (single !== undefined) {
            const dec = decode2231Enc(single)
            if (dec !== null) params.set(key, dec)
            continue
        }
        let buf = ''
        let valid = false
        for (let n = 0; ; n++) {
            const simple = `${key}*${n}`
            const sv = pieces.get(simple)
            if (sv !== undefined) {
                valid = true
                buf += sv
                continue
            }
            const ev = pieces.get(simple + '*')
            if (ev === undefined) break
            valid = true
            if (n === 0) {
                const dec = decode2231Enc(ev)
                if (dec !== null) buf += dec
            } else {
                buf += percentHexUnescape(ev)[0]
            }
        }
        if (valid) params.set(key, buf)
    }
    return { mediatype, params }
}

// ---- io and bufio ----

/** A Go error, compared by identity where Go compares with ==. */
type GoErr = Error | null

export const EOF = new Error('EOF')
const UNEXPECTED_EOF = new Error('unexpected EOF')
const BUFFER_FULL = new Error('bufio: buffer full')
const NO_PROGRESS = new Error('multiple Read calls return no data or error')
const MESSAGE_TOO_LARGE = new Error('message too large')

/** bufio's default size. */
const BUF_SIZE = 4096
/** io.Discard's read size, and the one io.ReadAll is given here; Go's results don't depend on it. */
const COPY_SIZE = 8192

/** An io.Reader: up to n bytes as a binary string, and an error. */
export interface GoReader {
    read(n: number): [string, GoErr]
}

// multipart's stickyErrorReader over a bytes.Reader.
class BytesReader implements GoReader {
    readonly #s: string
    #pos = 0
    #err: GoErr = null

    constructor(s: string) {
        this.#s = s
    }

    read(n: number): [string, GoErr] {
        if (this.#err !== null) return ['', this.#err]
        if (this.#pos >= this.#s.length) {
            this.#err = EOF
            return ['', EOF]
        }
        const out = this.#s.substr(this.#pos, n)
        this.#pos += out.length
        return [out, null]
    }
}

// bufio.Reader: data holds buf[0:w], and r is the read index.
class BufReader implements GoReader {
    readonly #rd: GoReader
    #data = ''
    #r = 0
    #err: GoErr = null

    constructor(rd: GoReader) {
        this.#rd = rd
    }

    buffered(): number {
        return this.#data.length - this.#r
    }

    #fill(): void {
        if (this.#r > 0) {
            this.#data = this.#data.slice(this.#r)
            this.#r = 0
        }
        if (this.#data.length >= BUF_SIZE) throw new Error('bufio: tried to fill full buffer')
        for (let i = 100; i > 0; i--) {
            const [d, err] = this.#rd.read(BUF_SIZE - this.#data.length)
            this.#data += d
            if (err !== null) {
                this.#err = err
                return
            }
            if (d.length > 0) return
        }
        this.#err = NO_PROGRESS
    }

    #readErr(): GoErr {
        const err = this.#err
        this.#err = null
        return err
    }

    peek(n: number): [string, GoErr] {
        while (this.buffered() < n && this.buffered() < BUF_SIZE && this.#err === null) this.#fill()
        if (n > BUF_SIZE) return [this.#data.slice(this.#r), BUFFER_FULL]
        let err: GoErr = null
        const avail = this.buffered()
        if (avail < n) {
            n = avail
            err = this.#readErr() ?? BUFFER_FULL
        }
        return [this.#data.substr(this.#r, n), err]
    }

    read(n: number): [string, GoErr] {
        if (n === 0) return ['', this.buffered() > 0 ? null : this.#readErr()]
        if (this.#r === this.#data.length) {
            if (this.#err !== null) return ['', this.#readErr()]
            if (n >= BUF_SIZE) {
                const [d, err] = this.#rd.read(n)
                this.#err = err
                return [d, this.#readErr()]
            }
            this.#r = 0
            this.#data = ''
            const [d, err] = this.#rd.read(BUF_SIZE)
            this.#err = err
            if (d.length === 0) return ['', this.#readErr()]
            this.#data = d
        }
        const out = this.#data.substr(this.#r, n)
        this.#r += out.length
        return [out, null]
    }

    readByte(): [string, GoErr] {
        while (this.#r === this.#data.length) {
            if (this.#err !== null) return ['', this.#readErr()]
            this.#fill()
        }
        return [this.#data[this.#r++] as string, null]
    }

    /** unreadByte follows a successful readByte, so the byte is still in the buffer. */
    unreadByte(): void {
        this.#r--
    }

    readSlice(): [string, GoErr] {
        let s = 0
        for (;;) {
            const i = this.#data.indexOf('\n', this.#r + s)
            if (i >= 0) {
                const line = this.#data.slice(this.#r, i + 1)
                this.#r = i + 1
                return [line, null]
            }
            if (this.#err !== null) {
                const line = this.#data.slice(this.#r)
                this.#r = this.#data.length
                return [line, this.#readErr()]
            }
            if (this.buffered() >= BUF_SIZE) {
                const line = this.#data.slice(this.#r)
                this.#r = this.#data.length
                return [line, BUFFER_FULL]
            }
            s = this.buffered()
            this.#fill()
        }
    }

    /** readLine is ReadLine: the line without its line end, whether it continues, and an error. */
    readLine(): [string | null, boolean, GoErr] {
        const [line, err] = this.readSlice()
        if (err === BUFFER_FULL) {
            if (line.endsWith('\r')) {
                this.#r--
                return [line.slice(0, -1), true, null]
            }
            return [line, true, null]
        }
        if (line.length === 0) return [err === null ? '' : null, false, err]
        if (!line.endsWith('\n')) return [line, false, null]
        return [line.slice(0, line.length > 1 && line[line.length - 2] === '\r' ? -2 : -1), false, null]
    }
}

function readAll(r: GoReader): [string, GoErr] {
    let out = ''
    for (;;) {
        const [d, err] = r.read(COPY_SIZE)
        out += d
        if (err !== null) return [out, err === EOF ? null : err]
    }
}

// io.Copy(io.Discard, r): reads until any error.
function drain(r: GoReader): void {
    for (;;) if (r.read(COPY_SIZE)[1] !== null) return
}

// ---- mime/quotedprintable ----

function fromHex(c: string): number | Error {
    if (isHex(c)) return parseInt(c, 16)
    return new Error(`quotedprintable: invalid hex byte 0x${c.charCodeAt(0).toString(16).padStart(2, '0')}`)
}

function readHexByte(v: string): number | Error {
    if (v.length < 2) return UNEXPECTED_EOF
    const hb = fromHex(v[0] as string)
    if (hb instanceof Error) return hb
    const lb = fromHex(v[1] as string)
    if (lb instanceof Error) return lb
    return (hb << 4) | lb
}

class QuotedPrintableReader implements GoReader {
    readonly #br: BufReader
    #line = ''
    #rerr: GoErr = null

    constructor(r: GoReader) {
        this.#br = new BufReader(r)
    }

    read(n: number): [string, GoErr] {
        let out = ''
        while (out.length < n) {
            if (this.#line.length === 0) {
                if (this.#rerr !== null) return [out, this.#rerr]
                let whole: string
                ;[whole, this.#rerr] = this.#br.readSlice()
                const hasLF = whole.endsWith('\n')
                const hasCR = whole.endsWith('\r\n')
                this.#line = whole.replace(/[\n\r \t]+$/, '')
                if (this.#line.endsWith('=')) {
                    const rightStripped = whole.slice(this.#line.length).replace(/^[ \t]+/, '')
                    this.#line = this.#line.slice(0, -1)
                    if (
                        !rightStripped.startsWith('\n') &&
                        !rightStripped.startsWith('\r\n') &&
                        !(rightStripped.length === 0 && this.#line.length > 0 && this.#rerr === EOF)
                    ) {
                        this.#rerr = new Error(`quotedprintable: invalid bytes after =: ${goQuote(rightStripped)}`)
                    }
                } else if (hasLF) {
                    this.#line += hasCR ? '\r\n' : '\n'
                }
                continue
            }
            let b = this.#line[0] as string
            const c = b.charCodeAt(0)
            if (b === '=') {
                const h = readHexByte(this.#line.slice(1))
                if (h instanceof Error) {
                    if (!(this.#line.length >= 2 && this.#line[1] !== '\r' && this.#line[1] !== '\n')) return [out, h]
                } else {
                    b = String.fromCharCode(h)
                    this.#line = this.#line.slice(2)
                }
            } else if (!(b === '\t' || b === '\r' || b === '\n' || c >= 0x80) && (c < 0x20 || c > 0x7e)) {
                return [out, new Error(`quotedprintable: invalid unescaped byte 0x${c.toString(16).padStart(2, '0')} in body`)]
            }
            out += b
            this.#line = this.#line.slice(1)
        }
        return [out, null]
    }
}

// ---- mime/multipart ----

const MAX_MIME_HEADER_SIZE = 10 << 20
const MAX_MIME_HEADERS = 10000

/** A part as multipart.Part: its form name and its reader. */
export interface Part {
    formName: string
    reader: GoReader
}

// The partReader's state, Part's n, total, err and readErr.
interface PartState {
    n: number
    total: number
    err: GoErr
    readErr: GoErr
}

/** MultipartReader is Go's multipart.Reader over a body held as a binary string. */
export class MultipartReader {
    readonly #br: BufReader
    #nl = '\r\n'
    #nlDashBoundary: string
    readonly #dashBoundary: string
    readonly #dashBoundaryDash: string
    #partsRead = 0
    #current: Part | undefined

    constructor(body: string, boundary: string) {
        this.#br = new BufReader(new BytesReader(body))
        this.#nlDashBoundary = '\r\n--' + boundary
        this.#dashBoundary = '--' + boundary
        this.#dashBoundaryDash = '--' + boundary + '--'
    }

    /**
     * nextPart is NextPart: the next part, or null where Go returns io.EOF,
     * which is the final boundary and also input that ends inside a header
     * block. It throws Go's other errors, by message.
     */
    nextPart(): Part | null {
        if (this.#current !== undefined) drain(this.#current.reader)
        if (this.#dashBoundary === '--') throw new Error('multipart: boundary is empty')
        let expectNewPart = false
        for (;;) {
            const [line, err] = this.#br.readSlice()
            if (err === EOF && this.#isFinalBoundary(line)) return null
            if (err !== null) throw new Error(`multipart: NextPart: ${err.message}`)
            if (this.#isBoundaryDelimiterLine(line)) {
                this.#partsRead++
                const part = this.#newPart()
                if (part === null) return null
                this.#current = part
                return part
            }
            if (this.#isFinalBoundary(line)) return null
            if (expectNewPart) throw new Error(`multipart: expecting a new Part; got line ${goQuote(line)}`)
            if (this.#partsRead === 0) continue
            if (line === this.#nl) {
                expectNewPart = true
                continue
            }
            throw new Error(`multipart: unexpected line in Next(): ${goQuote(line)}`)
        }
    }

    /** readAll is io.ReadAll of part; it throws the read's error. */
    readAll(part: Part): string {
        const [out, err] = readAll(part.reader)
        if (err !== null) throw err
        return out
    }

    /** drain is io.Copy(io.Discard, part), errors ignored. */
    drain(part: Part): void {
        drain(part.reader)
    }

    #isFinalBoundary(line: string): boolean {
        if (!line.startsWith(this.#dashBoundaryDash)) return false
        const rest = skipLWSP(line.slice(this.#dashBoundaryDash.length))
        return rest.length === 0 || rest === this.#nl
    }

    #isBoundaryDelimiterLine(line: string): boolean {
        if (!line.startsWith(this.#dashBoundary)) return false
        const rest = skipLWSP(line.slice(this.#dashBoundary.length))
        // A first boundary line ending in a bare LF switches the reader to LF.
        if (this.#partsRead === 0 && rest === '\n') {
            this.#nl = '\n'
            this.#nlDashBoundary = this.#nlDashBoundary.slice(1)
        }
        return rest === this.#nl
    }

    #newPart(): Part | null {
        const header = this.#readMIMEHeader()
        if (header === null) return null
        const get = (k: string) => header.get(k)?.[0] ?? ''
        const state: PartState = { n: 0, total: 0, err: null, readErr: null }
        let reader: GoReader = { read: (n) => this.#partRead(state, n) }
        // strings.EqualFold: no non-ASCII rune folds onto a letter of the name.
        if (asciiLower(get('Content-Transfer-Encoding')) === 'quoted-printable') {
            reader = new QuotedPrintableReader(reader)
        }
        return { formName: formName(get('Content-Disposition')), reader }
    }

    // partReader.Read.
    #partRead(p: PartState, len: number): [string, GoErr] {
        const br = this.#br
        while (p.n === 0 && p.err === null) {
            const [peek] = br.peek(br.buffered())
            ;[p.n, p.err] = scanUntilBoundary(peek, this.#dashBoundary, this.#nlDashBoundary, p.total, p.readErr)
            if (p.n === 0 && p.err === null) {
                const [, err] = br.peek(peek.length + 1)
                p.readErr = err === EOF ? UNEXPECTED_EOF : err
            }
        }
        if (p.n === 0) return ['', p.err]
        const [d] = br.read(Math.min(len, p.n))
        p.total += d.length
        p.n -= d.length
        return [d, p.n === 0 ? p.err : null]
    }

    // textproto's readMIMEHeader with multipart's limits; null where it
    // returns io.EOF.
    #readMIMEHeader(): Map<string, string[]> | null {
        const h = new Map<string, string[]>()
        this.#upcomingHeaderKeys()
        let maxMemory = MAX_MIME_HEADER_SIZE - 400
        let maxHeaders = MAX_MIME_HEADERS
        const [first, peekErr] = this.#br.peek(1)
        if (peekErr === null && (first === ' ' || first === '\t')) {
            const [line, err] = this.#readLineSlice(80)
            if (err !== null) return headerError(err)
            throw new Error(`malformed MIME header initial line: ${goQuote(line as string)}`)
        }
        for (;;) {
            const [kv, err] = this.#readContinuedLineSlice(maxMemory)
            if (kv === null || kv.length === 0) {
                if (err === null) return h
                return headerError(err)
            }
            const colon = kv.indexOf(':')
            const key = canonicalMIMEHeaderKey(kv.slice(0, colon))
            const v = kv.slice(colon + 1)
            if (key === null) throw new Error(`malformed MIME header line: ${goQuote(kv)}`)
            // Go canonicalizes the key in place, so the line it quotes carries it.
            if (!validHeaderValue(v)) throw new Error(`malformed MIME header line: ${goQuote(key + ':' + v)}`)
            if (--maxHeaders < 0) throw headerError(MESSAGE_TOO_LARGE)
            const value = v.replace(/^[ \t]+/, '')
            const vv = h.get(key)
            if (vv === undefined) maxMemory -= key.length + 200
            maxMemory -= value.length
            if (maxMemory < 0) throw headerError(MESSAGE_TOO_LARGE)
            if (vv === undefined) h.set(key, [value])
            else vv.push(value)
        }
    }

    // Peeks only to size a hint, but the peek fills the buffer, which moves
    // where later reads find their lines.
    #upcomingHeaderKeys(): void {
        this.#br.peek(1)
        const s = this.#br.buffered()
        if (s > 0) this.#br.peek(s)
    }

    #readLineSlice(lim: number): [string | null, GoErr] {
        let line: string | null = null
        for (;;) {
            const [l, more, err] = this.#br.readLine()
            if (err !== null) return [null, err]
            const part = l as string
            if (lim >= 0 && (line?.length ?? 0) + part.length > lim) return [null, MESSAGE_TOO_LARGE]
            if (line === null && !more) return [part, null]
            line = (line ?? '') + part
            if (!more) return [line, null]
        }
    }

    #readContinuedLineSlice(lim: number): [string | null, GoErr] {
        const [line, err] = this.#readLineSlice(lim)
        if (err !== null) return [null, err]
        if ((line as string).length === 0) return ['', null]
        if (!(line as string).includes(':')) {
            throw new Error(`malformed MIME header: missing colon: ${goQuote(line as string)}`)
        }
        if (this.#br.buffered() > 1) {
            const [peek] = this.#br.peek(2)
            const c = peek[0] ?? ''
            if ((peek.length > 0 && (/[A-Za-z]/.test(c) || c === '\n')) || peek === '\r\n') {
                return [trimLWSP(line as string), null]
            }
        }
        let buf = trimLWSP(line as string)
        lim -= buf.length
        while (this.#skipSpace() > 0) {
            buf += ' '
            if (buf.length >= lim) return [null, MESSAGE_TOO_LARGE]
            const [l, e] = this.#readLineSlice(lim - buf.length)
            if (e !== null) break
            buf += trimLWSP(l as string)
        }
        return [buf, null]
    }

    #skipSpace(): number {
        let n = 0
        for (;;) {
            const [c, err] = this.#br.readByte()
            if (err !== null) return n
            if (c !== ' ' && c !== '\t') {
                this.#br.unreadByte()
                return n
            }
            n++
        }
    }
}

// populateHeaders: io.EOF passes through unwrapped, which NextPart's caller
// reads as the end, and textproto's size error becomes multipart's.
function headerError(err: Error): null {
    if (err === EOF) return null
    if (err === MESSAGE_TOO_LARGE) throw new Error('multipart: message too large')
    throw err
}

function scanUntilBoundary(
    buf: string,
    dashBoundary: string,
    nlDashBoundary: string,
    total: number,
    readErr: GoErr,
): [number, GoErr] {
    if (total === 0) {
        if (buf.startsWith(dashBoundary)) {
            switch (matchAfterPrefix(buf, dashBoundary, readErr)) {
                case -1:
                    return [dashBoundary.length, null]
                case 0:
                    return [0, null]
                case 1:
                    return [0, EOF]
            }
        }
        if (dashBoundary.startsWith(buf)) return [0, readErr]
    }
    const i = buf.indexOf(nlDashBoundary)
    if (i >= 0) {
        switch (matchAfterPrefix(buf.slice(i), nlDashBoundary, readErr)) {
            case -1:
                return [i + nlDashBoundary.length, null]
            case 0:
                return [i, null]
            case 1:
                return [i, EOF]
        }
    }
    if (nlDashBoundary.startsWith(buf)) return [0, readErr]
    const j = buf.lastIndexOf(nlDashBoundary[0] as string)
    if (j >= 0 && nlDashBoundary.startsWith(buf.slice(j))) return [j, null]
    return [buf.length, readErr]
}

function matchAfterPrefix(buf: string, prefix: string, readErr: GoErr): number {
    if (buf.length === prefix.length) return readErr !== null ? 1 : 0
    const c = buf[prefix.length]
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') return 1
    if (c === '-') {
        if (buf.length === prefix.length + 1) return readErr !== null ? -1 : 0
        if (buf[prefix.length + 1] === '-') return 1
    }
    return -1
}

function skipLWSP(s: string): string {
    let i = 0
    while (i < s.length && (s[i] === ' ' || s[i] === '\t')) i++
    return s.slice(i)
}

function trimLWSP(s: string): string {
    return s.replace(/^[ \t]+/, '').replace(/[ \t]+$/, '')
}

function asciiLower(s: string): string {
    return s.replace(/[A-Z]/g, (c) => c.toLowerCase())
}

function validHeaderFieldByte(c: number): boolean {
    return c < 0x80 && /[!#$%&'*+\-.^_`|~0-9A-Za-z]/.test(String.fromCharCode(c))
}

function validHeaderValue(v: string): boolean {
    for (let i = 0; i < v.length; i++) {
        const c = v.charCodeAt(i)
        if (c === 0x7f || (c < 0x20 && c !== 0x09)) return false
    }
    return true
}

// A key with a space is kept as written, so Header.Get never finds it.
function canonicalMIMEHeaderKey(k: string): string | null {
    if (k === '') return null
    let noCanon = false
    for (let i = 0; i < k.length; i++) {
        const c = k.charCodeAt(i)
        if (validHeaderFieldByte(c)) continue
        if (c === 0x20) {
            noCanon = true
            continue
        }
        return null
    }
    if (noCanon) return k
    let out = ''
    let upper = true
    for (const ch of k) {
        out += upper ? ch.toUpperCase() : ch.toLowerCase()
        upper = ch === '-'
    }
    return out
}

function formName(disposition: string): string {
    try {
        const { mediatype, params } = parseMediaType(disposition)
        return mediatype === 'form-data' ? (params.get('name') ?? '') : ''
    } catch {
        return ''
    }
}
