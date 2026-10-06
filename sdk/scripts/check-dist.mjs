#!/usr/bin/env node
// Checks the built package the way a consumer resolves it: by its name, through
// package.json's "imports" and "exports". The unit tests alias #default-fetch to
// source, so this is the only check that the published map hands Node the
// guarded fetch and Bun the plain one.
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

try {
    const outcome = await resolveConfig({ signer, network: testnet() })
        .fetch(url)
        .then(
            (r) => r.text(),
            (e) => (nodeEntry && e?.cause instanceof nodeEntry.PrivateTargetError ? 'PrivateTargetError' : String(e?.cause ?? e)),
        )
    const want = mode === 'guarded' ? 'PrivateTargetError' : 'reached'
    if (outcome !== want) fail(`${where}: the default fetch to ${url} gave ${outcome}, want ${want}`)
    console.log(`check-dist: ${where}: ${mode} (${outcome})`)
} finally {
    server.close()
}
