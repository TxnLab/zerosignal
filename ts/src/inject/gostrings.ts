/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * goTrimSpace is Go's strings.TrimSpace: it strips unicode.IsSpace at both
 * ends. Not String.prototype.trim, which also strips U+FEFF and keeps U+0085,
 * so a value Go reads as hex after trimming would fail to decode here.
 */
export function goTrimSpace(s: string): string {
  let i = 0
  let j = s.length
  while (i < j && isGoSpace(s.charCodeAt(i))) i++
  while (j > i && isGoSpace(s.charCodeAt(j - 1))) j--
  return s.slice(i, j)
}

function isGoSpace(c: number): boolean {
  return (
    (c >= 0x09 && c <= 0x0d) ||
    c === 0x20 ||
    c === 0x85 ||
    c === 0xa0 ||
    c === 0x1680 ||
    (c >= 0x2000 && c <= 0x200a) ||
    c === 0x2028 ||
    c === 0x2029 ||
    c === 0x202f ||
    c === 0x205f ||
    c === 0x3000
  )
}
