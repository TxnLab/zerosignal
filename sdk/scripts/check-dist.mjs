#!/usr/bin/env node
// Checks the built package the way a consumer resolves it: by its name, through
// package.json's "imports" and "exports". The unit tests alias #default-fetch to
// source, so this is the only check that the published map hands Node the
// guarded fetch and Bun the plain one, which checks only the URL's host.
//
//   node scripts/check-dist.mjs           guarded (Node's conditions)
//   node --conditions=bun scripts/...     plain   (Bun's map entry, from Node)
//   node --conditions=deno scripts/...    plain   (Deno's, likewise)
//   bun scripts/check-dist.mjs            plain   (Bun itself, when installed)
//
// Run after `pnpm build`. With no argument it runs all three.

import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { fileURLToPath } from 'node:url'

const self = fileURLToPath(import.meta.url)
const pkgDir = fileURLToPath(new URL('..', import.meta.url))
const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))

function fail(msg) {
    console.error(`check-dist: ${msg}`)
    process.exit(1)
}

const mode = process.argv[2]
if (!mode) {
    // The order is the resolution: the first matching condition wins, and Bun
    // and Deno match "node" too.
    const entry = pkg.imports['#default-fetch']
    const order = Object.keys(entry).join(',')
    if (order !== 'types,bun,deno,node,default') fail(`#default-fetch conditions are ${order}`)
    for (const target of Object.values(entry)) {
        if (!existsSync(new URL(`../${target}`, import.meta.url))) fail(`${target} is missing: run pnpm build`)
    }
    // Every named subpath points at a built file; a new src directory the
    // build config leaves out would otherwise publish an export that 404s.
    for (const [key, sub] of Object.entries(pkg.exports)) {
        if (typeof sub !== 'object' || key.includes('*')) continue
        for (const target of Object.values(sub)) {
            if (!existsSync(new URL(`../${target}`, import.meta.url))) fail(`export ${key}: ${target} is missing`)
        }
    }
    const runs = [
        [process.execPath, [self, 'guarded']],
        [process.execPath, ['--conditions=bun', self, 'plain']],
        [process.execPath, ['--conditions=deno', self, 'plain']],
    ]
    if (spawnSync('bun', ['--version']).status === 0) runs.push(['bun', [self, 'plain']])
    for (const [cmd, args] of runs) {
        const r = spawnSync(cmd, args, { cwd: pkgDir, stdio: 'inherit' })
        if (r.status !== 0) fail(`${cmd} ${args.join(' ')} failed`)
    }
    process.exit(0)
}

const { resolveConfig, testnet } = await import(pkg.name)
const server = createServer((_, res) => res.end('reached')).listen(0, '127.0.0.1')
await new Promise((r) => server.once('listening', r))
const url = `http://127.0.0.1:${server.address().port}/`
const signer = { address: 'PAYER', signBytes: async () => new Uint8Array(), signTransactions: async () => [] }
const where = `${typeof Bun === 'undefined' ? 'node' : 'bun'} ${process.execArgv.join(' ')}`.trim()

// The subpath the README sends a Node user to, whose error class is the one a
// refusal must carry.
const nodeEntry = mode === 'guarded' ? await import(`${pkg.name}/node`) : undefined
if (nodeEntry && typeof nodeEntry.nodeFetch !== 'function') fail(`${pkg.name}/node exports no nodeFetch`)

// The account subpaths load by name under every runtime's conditions.
for (const [sub, fn] of [
    ['accounts/algosdk', 'algosdkSigner'],
    ['accounts/mnemonic', 'mnemonicSigner'],
    ['accounts/xhd', 'xhdSigner'],
]) {
    const m = await import(`${pkg.name}/${sub}`)
    if (typeof m[fn] !== 'function') fail(`${pkg.name}/${sub} exports no ${fn}`)
}

// The TEE chain step imports @phala/dcap-qvl lazily, so nothing above loads
// it. It is CommonJS: check it loads under this runtime's ESM loader, then that
// the dist's own loader reaches verify (a wrong interop shape would surface as
// "is not a function", not as the library refusing a junk quote).
{
    const qvlMod = await import('@phala/dcap-qvl')
    const qvl = qvlMod.default ?? qvlMod
    for (const fn of ['verify', 'getCollateral']) {
        if (typeof qvl[fn] !== 'function') fail(`@phala/dcap-qvl exports no ${fn} function`)
    }
    // The collateral cache keys by these; without them every quote goes uncached.
    if (typeof qvl.Quote?.parse !== 'function') fail('@phala/dcap-qvl exports no Quote.parse')
    for (const fn of ['getFmspc', 'getCa']) {
        if (typeof qvl.intel?.[fn] !== 'function') fail(`@phala/dcap-qvl exports no intel.${fn}`)
    }
    const { carriedChainVerifier } = await import(`${pkg.name}/tee`)
    if (typeof carriedChainVerifier !== 'function') fail(`${pkg.name}/tee exports no carriedChainVerifier`)
    const refused = await carriedChainVerifier()(new Uint8Array(8), {}).then(
        () => 'passed',
        (e) => String(e?.message ?? e),
    )
    if (refused !== 'Failed to decode quote') fail(`the dist's dcap-qvl verify gave ${refused}, want the library's own refusal`)
}

// One class, whichever entry a caller imports it from.
const { PrivateTargetError } = await import(pkg.name)
if (typeof PrivateTargetError !== 'function') fail(`${pkg.name} exports no PrivateTargetError`)
if (nodeEntry && nodeEntry.PrivateTargetError !== PrivateTargetError) fail(`${pkg.name}/node's PrivateTargetError is not the root's`)

// Both builds refuse a loopback literal; where they refuse it tells them apart.
// The guarded fetch refuses at the dial, so fetch rejects with a TypeError
// whose cause is the refusal; the plain one refuses the URL before fetching.
// By name, not class: Bun applies this checkout's tsconfig "paths", so there
// #default-fetch loads from src with its own copy of the class. The published
// package carries no tsconfig.
async function outcomeOf(allowPrivateHosts) {
    return resolveConfig({ signer, network: testnet(), allowPrivateHosts })
        .fetch(url)
        .then(
            (r) => r.text(),
            (e) =>
                e?.cause?.name === 'PrivateTargetError'
                    ? 'refused at the dial'
                    : e?.name === 'PrivateTargetError'
                      ? 'refused on the URL'
                      : String(e?.cause ?? e),
        )
}

try {
    const refused = await outcomeOf(false)
    const want = mode === 'guarded' ? 'refused at the dial' : 'refused on the URL'
    if (refused !== want) fail(`${where}: the default fetch to ${url} gave ${refused}, want ${want}`)
    const allowed = await outcomeOf(true)
    if (allowed !== 'reached') fail(`${where}: with allowPrivateHosts the default fetch to ${url} gave ${allowed}, want reached`)
    console.log(`check-dist: ${where}: ${mode} (${refused})`)
} finally {
    server.close()
}
