#!/usr/bin/env bash
# Fails when ts/ and sdk/ would not release as a matching pair.
#
# sdk/ pins @txnlab/zs-proto at exactly its own version (workspace:*, which
# `pnpm pack` / `pnpm publish` rewrite to ts/'s version). Two implementations
# that must agree byte-for-byte have no valid combination other than the
# matching pair, so the versions must be equal, and the dependency must stay
# workspace:* rather than a range or a hand-written number that drifts.
#
# Only pnpm rewrites workspace:*. A tarball built by `npm pack` or published
# by `npm publish` from sdk/ ships the literal and cannot be installed, so a
# release job must `pnpm pack` and publish that tarball.
set -euo pipefail
cd "$(dirname "$0")/.."

node --input-type=module -e '
import { readFileSync } from "node:fs"
const ts = JSON.parse(readFileSync("ts/package.json", "utf8"))
const sdk = JSON.parse(readFileSync("sdk/package.json", "utf8"))
const bad = []
if (ts.version !== sdk.version) bad.push(`ts/ is ${ts.version}, sdk/ is ${sdk.version}`)
const dep = sdk.dependencies?.[ts.name]
if (dep !== "workspace:*") bad.push(`sdk/ depends on ${ts.name} as ${JSON.stringify(dep)}, want "workspace:*"`)
if (bad.length) {
  console.error("ts/ and sdk/ must release in lockstep:\n  " + bad.join("\n  "))
  process.exit(1)
}
'
