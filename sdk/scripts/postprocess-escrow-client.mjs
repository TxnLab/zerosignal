// Post-processes the generated ZeroSignalEscrowClient.ts so its emitted JS links.
// The algokit-client-generator emits `import { Type, runtimeFn }` mixed-purpose
// imports; tsc under verbatimModuleSyntax (and Rolldown in a consumer's bundle)
// keeps every named import as runtime, so types like `Arc56Contract` (which the
// source .mjs files re-export only as types) fail to resolve at load time.
//
// This script:
//   1. inserts `// @ts-nocheck` once after `/* eslint-disable */` so the
//      file's own non-strict shape doesn't fail the project tsc;
//   2. parses the file with the TypeScript compiler API and rewrites each
//      mixed import declaration into a runtime `import { ... }` plus a
//      type-only `import type { ... }`, classifying each named binding via
//      the RUNTIME_SYMBOLS allowlist below;
//   3. strips trailing whitespace, which the generator emits on JSDoc
//      continuation lines (sourced from arc56 `desc` fields). The file is
//      `/* eslint-disable */`, so eslint's no-trailing-spaces never runs, and
//      Prettier leaves block-comment interiors verbatim — neither tool cleans
//      it, so the strip lives here to keep `gen:client` output idempotent. The
//      generated client has no multi-line template literals, so a line-end
//      strip can never touch string content.
//
// Re-run via `pnpm gen:client`. The script is idempotent. If a future
// generator version pulls in a *new runtime* symbol, add it to
// RUNTIME_SYMBOLS — type-only additions need no change.

import { readFileSync, writeFileSync } from 'node:fs'
import ts from 'typescript'

// Original (pre-alias) names of values that exist at runtime. Anything not
// in this set is treated as a type-only import.
const RUNTIME_SYMBOLS = new Set([
  'getArc56ReturnValue',
  'getABIStructFromABITuple',
  'AppClient',
  'AppFactory',
  'TransactionComposer',
  'encodeAddress',
  'modelsv2',
  'OnApplicationComplete',
])

const file = process.argv[2]
if (!file) {
  console.error('usage: postprocess-escrow-client.mjs <path>')
  process.exit(1)
}

let src = readFileSync(file, 'utf8')

if (!src.includes('// @ts-nocheck')) {
  src = src.replace(/^\/\* eslint-disable \*\/\n/, '/* eslint-disable */\n// @ts-nocheck\n')
}

const sf = ts.createSourceFile(
  file,
  src,
  ts.ScriptTarget.Latest,
  /* setParentNodes */ false,
  ts.ScriptKind.TS,
)

const edits = []

for (const stmt of sf.statements) {
  if (!ts.isImportDeclaration(stmt)) continue

  const clause = stmt.importClause
  if (!clause) continue // side-effect import
  if (clause.isTypeOnly) continue // already `import type`
  if (clause.name) continue // has a default binding; leave alone

  const named = clause.namedBindings
  if (!named || !ts.isNamedImports(named)) continue // namespace import

  const moduleText = stmt.moduleSpecifier.getText(sf)
  const runtime = []
  const types = []
  for (const el of named.elements) {
    const importedName = (el.propertyName ?? el.name).text
    // Reconstruct the specifier without any inline `type` modifier — the
    // outer `import type` (or runtime classification) makes it redundant.
    const specText = el.propertyName ? `${el.propertyName.text} as ${el.name.text}` : el.name.text
    // Inline `type` modifier or allowlist miss → type-only.
    if (!el.isTypeOnly && RUNTIME_SYMBOLS.has(importedName)) runtime.push(specText)
    else types.push(specText)
  }

  if (runtime.length && types.length) {
    edits.push({
      start: stmt.getStart(sf),
      end: stmt.getEnd(),
      text:
        `import { ${runtime.join(', ')} } from ${moduleText}\n` +
        `import type { ${types.join(', ')} } from ${moduleText}`,
    })
  } else if (types.length) {
    edits.push({
      start: stmt.getStart(sf),
      end: stmt.getEnd(),
      text: `import type { ${types.join(', ')} } from ${moduleText}`,
    })
  }
  // all-runtime: leave the original declaration untouched
}

edits.sort((a, b) => b.start - a.start)
for (const { start, end, text } of edits) {
  src = src.slice(0, start) + text + src.slice(end)
}

// Strip trailing whitespace from every line (see header note 3).
src = src.replace(/[ \t]+$/gm, '')

writeFileSync(file, src)
