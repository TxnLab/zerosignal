/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The chain and escrow application, mirroring proto/go/zs Network and
// proto/go/algod's presets (pinned by testdata/sdk_vocabulary_vectors.json).

import { configError } from './errors.js'

export type NetworkName = 'localnet' | 'testnet' | 'mainnet'

/** The chain family an escrow runs on, as Go's zs.RailName spells it. */
export type Rail = 'algorand' | 'solana'

/**
 * The coin a rail's network fees are paid in. A fee amount is in its base
 * units, decimals of them to the coin.
 */
export interface FeeUnit {
    currency: string
    decimals: number
}

/** feeUnitOf is rail's fee unit. */
export function feeUnitOf(rail: Rail): FeeUnit {
    return rail === 'solana' ? { currency: 'SOL', decimals: 9 } : { currency: 'ALGO', decimals: 6 }
}

/**
 * Network selects the chain and the escrow application. An empty Network is
 * mainnet, the production network. Naming a preset is enough; algodEndpoint
 * and algodToken override its algod. escrowAppId is embedded for testnet and
 * mainnet only, so localnet or a private deployment must set it. Asset ids
 * are never configured: they are read from the contract's global state.
 */
export interface Network {
    /** Absent is algorand, the only rail supported today. */
    rail?: Rail
    network?: NetworkName
    algodEndpoint?: string
    algodToken?: string
    escrowAppId?: bigint
}

export interface ResolvedNetwork {
    rail: Rail
    /** Empty when the chain was named only by its endpoint. */
    network: NetworkName | ''
    /**
     * The network key names, which follows the app id rather than the name
     * the config used (see resolveNetwork).
     */
    label: string
    /**
     * Names the deployment's local state: the saved catalog, journal rows.
     * Readable rather than a hash of the deployment id, because a host loads
     * that state before anything reads the chain, and a localnet's genesis is
     * per instance. Never signed and never sent.
     */
    key: string
    /**
     * The name the same state had before keys carried the rail and network:
     * the bare app id on Algorand, empty on a rail that had none.
     */
    legacyKey: string
    algodEndpoint: string
    algodToken: string
    escrowAppId: bigint
    /**
     * The genesis fee sink of a public network, the sender of read-only
     * simulates that must succeed before the payer holds any ALGO. Empty for
     * localnet and private networks.
     */
    feeSink: string
    /** Settings that resolve but are probably not what the caller meant. */
    warnings: string[]
}

const presets: Record<NetworkName, { algodEndpoint: string; algodToken: string; escrowAppId: bigint; feeSink: string }> = {
    localnet: {
        algodEndpoint: 'http://localhost:4001',
        algodToken: 'a'.repeat(64),
        escrowAppId: 0n,
        feeSink: '',
    },
    testnet: {
        algodEndpoint: 'https://testnet-api.4160.nodely.dev',
        algodToken: '',
        escrowAppId: 765860477n,
        feeSink: 'A7NMWS3NT3IUDMLVO26ULGXGIIOUQ3ND2TXSER6EBGRZNOBOUIQXHIBGDE',
    },
    mainnet: {
        algodEndpoint: 'https://mainnet-api.4160.nodely.dev',
        algodToken: '',
        escrowAppId: 3628061142n,
        feeSink: 'Y76M3MSY6DKBRHBL7C3NNDXGS5IIMQVQVUAB6MP4XEMMGVF2QWNPL226CA',
    },
}

/** The presets, in the order Go lists them. */
export const networkNames: readonly NetworkName[] = ['localnet', 'testnet', 'mainnet']

const MAX_UINT64 = (1n << 64n) - 1n

export const mainnet = (): Network => ({ network: 'mainnet' })
export const testnet = (): Network => ({ network: 'testnet' })
export const localnet = (): Network => ({ network: 'localnet' })

/**
 * resolveNetwork applies the preset and the overrides, or throws a ZsError.
 *
 * The label in key is the preset an app id belongs to, so a config naming
 * mainnet and one naming only its endpoint share state. Any other app id takes
 * the network the config names, since app ids are per network and testnet's
 * app 42 is not mainnet's. Only an endpoint alone is "custom", which splits
 * that config's state from the same deployment named as localnet; the cost is
 * rows left under the other key, not rows lost.
 */
export function resolveNetwork(n: Network = {}): ResolvedNetwork {
    const rail = n.rail ?? 'algorand'
    if (rail !== 'algorand') {
        throw configError(`Network.rail ${String(rail)} is not supported yet`)
    }
    // Lowered but not trimmed, as Go's algod.Config.Resolve does: a blank
    // name is a mistake to refuse, not an absent one to read as mainnet.
    let name = n.network?.toLowerCase() ?? ''
    if (n.escrowAppId !== undefined && (typeof n.escrowAppId !== 'bigint' || n.escrowAppId < 0n || n.escrowAppId > MAX_UINT64)) {
        throw configError(`Network.escrowAppId must be a uint64 bigint, got ${String(n.escrowAppId)}`)
    }
    if (name === '' && !n.algodEndpoint) {
        // Only a Network left wholly unset means mainnet. A token or an app id
        // on its own was meant for some chain, and guessing mainnet for it
        // would pay there.
        if (n.algodToken || n.escrowAppId) {
            throw configError('Network.network or algodEndpoint is required when algodToken or escrowAppId is set')
        }
        name = 'mainnet'
    }
    if (name !== '' && !Object.hasOwn(presets, name)) {
        throw configError(`network must be one of localnet|testnet|mainnet (case-insensitive), got ${JSON.stringify(n.network)}`)
    }
    const p = name === '' ? undefined : presets[name as NetworkName]
    const warnings: string[] = []
    let escrowAppId = n.escrowAppId ?? 0n
    if (escrowAppId === 0n) {
        escrowAppId = p?.escrowAppId ?? 0n
        if (p && n.algodEndpoint) {
            warnings.push(
                `Network.algodEndpoint overrides the ${name} preset but the escrow app id is still that preset's (${escrowAppId}); set Network.escrowAppId if the endpoint is another chain`,
            )
        }
    }
    if (escrowAppId === 0n) {
        throw configError('Network.escrowAppId is required for this network')
    }
    const label = deploymentLabel(escrowAppId, name)
    return {
        rail,
        network: name as NetworkName | '',
        label,
        key: `${rail}-${label}-${escrowAppId}`,
        legacyKey: String(escrowAppId),
        algodEndpoint: n.algodEndpoint ? n.algodEndpoint.replace(/\/+$/, '') : (p?.algodEndpoint ?? ''),
        algodToken: n.algodToken || (p?.algodToken ?? ''),
        escrowAppId,
        feeSink: p?.feeSink ?? '',
        warnings,
    }
}

function deploymentLabel(appId: bigint, named: string): string {
    for (const p of ['testnet', 'mainnet'] as const) {
        if (presets[p].escrowAppId === appId) return p
    }
    return named === '' ? 'custom' : named
}

/**
 * ownsRecord reports whether a journal row belongs to deployment d. A row
 * written before rows named their deployment (deployment absent or empty, as
 * in a store a 0.6 SDK wrote) matches on the app id alone, which is how it was
 * scoped then.
 */
export function ownsRecord(d: ResolvedNetwork, rec: { deployment?: string | undefined; escrowAppId: bigint }): boolean {
    if (rec.deployment) return rec.deployment === d.key
    return d.rail === 'algorand' && rec.escrowAppId === d.escrowAppId
}
