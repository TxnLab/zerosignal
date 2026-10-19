/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Lists the network's nodes and the models they serve, as a payer's router
// sees them, without paying anything or holding a key: the chain read, one
// probe cycle, and the catalog saved for the next run.
//
//   pnpm start [--network mainnet|testnet] [--catalog ./catalog.json]

import { readFile, rename, writeFile } from 'node:fs/promises'
import { parseArgs } from 'node:util'

import {
    ChainOperatorSource,
    DiscoveryRegistry,
    type NetworkName,
    type Operator,
    type StorageAdapter,
    catalogStorageKey,
    isTeeAttested,
    resolveNetwork,
    retryingAlgod,
} from '@txnlab/zerosignal'
import { reachabilityOf } from '@txnlab/zerosignal/catalog'
import { defaultVerifier } from '@txnlab/zerosignal/tee'

const { values } = parseArgs({
    options: {
        network: { type: 'string', default: 'mainnet' },
        catalog: { type: 'string', default: './catalog.json' },
    },
})

// The registry saves its catalog through this port, so the next run starts
// from the nodes this one saw, even before the chain read returns.
function fileStorage(path: string): StorageAdapter {
    const read = async (): Promise<Record<string, string>> => {
        try {
            return JSON.parse(await readFile(path, 'utf8')) as Record<string, string>
        } catch {
            return {}
        }
    }
    const write = async (all: Record<string, string>) => {
        // Through a temp file, so a crash mid-write leaves the old catalog.
        await writeFile(`${path}.tmp`, JSON.stringify(all))
        await rename(`${path}.tmp`, path)
    }
    return {
        get: async (key) => (await read())[key],
        set: async (key, value) => write({ ...(await read()), [key]: value }),
        delete: async (key) => {
            const all = await read()
            delete all[key]
            await write(all)
        },
    }
}

const net = resolveNetwork({ network: values.network as NetworkName })
const discovery = { maxCarryAge: 0 } // 0 takes the default; reachabilityOf reads the same value
const source = new ChainOperatorSource({
    algod: retryingAlgod({ endpoint: net.algodEndpoint, token: net.algodToken }),
    escrowAppId: net.escrowAppId,
    // Probes go through a relay by default, so the nodes never see this
    // machine's address; 'direct' would show it to each one.
    privacy: 'relay_required',
    teeVerifier: defaultVerifier(),
})
const registry = new DiscoveryRegistry({
    source,
    storage: fileStorage(values.catalog),
    storageKey: catalogStorageKey(net),
    legacyStorageKey: catalogStorageKey(net.legacyKey),
    discovery,
})

// ready is the saved catalog plus one chain read; a read of the registry
// then waits for the first probe of every node.
await registry.ready
const operators = await registry.allOperators()
const now = Date.now()

const row = (op: Operator) => {
    const tee = op.tee === undefined ? '-' : isTeeAttested(op) ? 'attested' : `unattested (${op.tee.failureTag || 'checks'})`
    return {
        node: `${op.id}/${op.nodeId}`,
        reachability: reachabilityOf(op, now, discovery.maxCarryAge),
        version: op.protoVersion || '-',
        tee,
        staging: op.staging ? 'yes' : '',
        models: op.models.length,
        url: op.baseUrl,
    }
}
console.table(operators.map(row))

// What a router would offer now: the advertisable nodes' models, merged.
const models = await registry.allModels()
console.log(`\n${models.length} models routable on ${net.network}:`)
for (const m of models) console.log(`  ${m}`)

await registry.stop()
