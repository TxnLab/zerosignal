// Writes the escrow app's ABI method signatures and its approval program's
// assert messages by program counter, from the in-repo ARC-56, into $1. Go's
// escrow/embed.go reads the same two things from the same file at run time;
// the SDK takes them as a generated module so the algod chain needs no
// algokit at run time and no 450 KB JSON in a consumer's bundle.
//
// `pnpm gen:client` writes the committed copy; `make check-escrow-client`
// regenerates to a scratch file and compares.

import { readFileSync, writeFileSync } from 'node:fs'

const out = process.argv[2]
if (!out) {
    console.error('usage: gen-escrow-abi.mjs <output.ts>')
    process.exit(1)
}

const arc56 = JSON.parse(readFileSync(new URL('../../go/escrow/ZeroSignalEscrow.arc56.json', import.meta.url), 'utf8'))

// Go's methodSignature: the ARC-56 arg types verbatim, "void" for none.
const signatures = arc56.methods
    .map((m) => [m.name, `${m.name}(${m.args.map((a) => a.type).join(',')})${m.returns.type || 'void'}`])
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))

const byMessage = new Map()
for (const e of arc56.sourceInfo.approval.sourceInfo) {
    if (!e.errorMessage) continue
    const pcs = byMessage.get(e.errorMessage) ?? []
    pcs.push(...e.pc)
    byMessage.set(e.errorMessage, pcs)
}
const messages = [...byMessage.entries()]
    .map(([msg, pcs]) => [msg, [...new Set(pcs)].sort((a, b) => a - b)])
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))

const lines = [
    '/*',
    ' * Copyright (c) 2026. TxnLab Inc.',
    ' * SPDX-License-Identifier: Apache-2.0',
    ' */',
    '',
    `// Generated from go/escrow/ZeroSignalEscrow.arc56.json (${arc56.name}) by`,
    '// scripts/gen-escrow-abi.mjs. Do not edit; run `pnpm gen:client`.',
    '',
    '/** Each ABI method\'s canonical signature, by name. */',
    'export const ESCROW_METHOD_SIGNATURES: Readonly<Record<string, string>> = {',
    ...signatures.map(([name, sig]) => `    ${JSON.stringify(name)}: ${JSON.stringify(sig)},`),
    '}',
    '',
    '/** The approval program\'s assert messages, each with the program counters that raise it. */',
    'export const APPROVAL_ERROR_PCS: ReadonlyArray<readonly [string, readonly number[]]> = [',
    ...messages.map(([msg, pcs]) => `    [${JSON.stringify(msg)}, [${pcs.join(', ')}]],`),
    ']',
    '',
]
writeFileSync(out, lines.join('\n'))
