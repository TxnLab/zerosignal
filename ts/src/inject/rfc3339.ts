/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Go's time.Parse(time.RFC3339, s), so the bundle decode and the collateral
// dating accept exactly the strings Go accepts. time.Time's UnmarshalJSON
// matches it only because Go has its stricter RFC 3339 checks switched off
// (go.dev/issue/54580); if a release turns them on, the generated_at bundle
// vectors go stale and say so. Date.parse cannot stand in: it takes a date with no time, lowercase
// separators and out-of-range days, and a verifier that dates a document Go
// refuses to date judges it by a different floor.
//
// Go is looser than the RFC in three places, and this matches it: a one-digit
// hour, a comma before the fraction, and zone offsets up to +24:00 and :60.
// Digits past the ninth fractional digit are dropped, not rounded.
//
// Pinned against Go by the rfc3339 block of proto/testdata/tee_bundle_vectors.json.

const RFC3339_RE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{1,2}):(\d{2}):(\d{2})(?:[.,](\d+))?(?:Z|([+-])(\d{2}):(\d{2}))$/

const NANOS_PER_SECOND = 1_000_000_000n

/**
 * parseRFC3339 returns the instant s names as nanoseconds since the Unix epoch,
 * or null when Go would refuse s. Nanoseconds rather than a Date because Go
 * compares at that precision, and a bound checked in milliseconds moves the
 * edge by up to a millisecond.
 */
export function parseRFC3339(s: string): bigint | null {
  const m = RFC3339_RE.exec(s)
  if (!m) return null
  const year = Number(m[1])
  const month = Number(m[2])
  const day = Number(m[3])
  const hour = Number(m[4])
  const minute = Number(m[5])
  const second = Number(m[6])
  if (month < 1 || month > 12) return null
  if (day < 1 || day > daysIn(month, year)) return null
  if (hour > 23 || minute > 59 || second > 59) return null

  let offsetSec = 0
  if (m[8] !== undefined) {
    const oh = Number(m[9])
    const om = Number(m[10])
    if (oh > 24 || om > 60) return null
    offsetSec = (oh * 60 + om) * 60
    if (m[8] === '-') offsetSec = -offsetSec
  }

  const nanos = m[7] === undefined ? 0n : BigInt(m[7].slice(0, 9).padEnd(9, '0'))
  const secs =
    daysFromCivil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second - offsetSec
  return BigInt(secs) * NANOS_PER_SECOND + nanos
}

/** epochNanosFromMillis converts a Date.now()-style instant for comparison with
 *  parseRFC3339's result. */
export function epochNanosFromMillis(ms: number): bigint {
  return BigInt(Math.trunc(ms)) * 1_000_000n
}

function isLeap(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
}

function daysIn(month: number, year: number): number {
  if (month === 2) return isLeap(year) ? 29 : 28
  return month === 4 || month === 6 || month === 9 || month === 11 ? 30 : 31
}

// Days from 1970-01-01 to a proleptic Gregorian date, for every year Go's
// four-digit layout can express (0000-9999).
function daysFromCivil(year: number, month: number, day: number): number {
  const y = month <= 2 ? year - 1 : year
  const era = Math.floor(y / 400)
  const yoe = y - era * 400
  const mp = (month + 9) % 12
  const doy = Math.floor((153 * mp + 2) / 5) + day - 1
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy
  return era * 146097 + doe - 719468
}
