/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The chain and escrow application, mirroring proto/go/zs Network and
// proto/go/algod's presets, and proto/go/solana/zsescrow's cluster presets
// (pinned by testdata/sdk_vocabulary_vectors.json).

import { base64 as scureBase64 } from '@scure/base'
import { encodeBase58, publicKeyBytes } from '@txnlab/zs-proto/solana'
import { DEVNET_PROGRAM_ID, PROGRAM_ID } from '@txnlab/zs-proto/solana/zsescrow'

import { configError } from './errors.js'
import { isLoopbackAddress } from './privateip.js'

/** An Algorand preset. */
export type NetworkName = 'localnet' | 'testnet' | 'mainnet'

/** A Solana cluster preset. */
export type SolanaClusterName = 'devnet' | 'localnet'

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
 *
 * rail solana reads network as a cluster preset (devnet or localnet), and
 * rpcEndpoint and program in place of the algod fields; there is no
 * zero-value cluster, so a Solana Network names its cluster or its endpoint.
 * rpcEndpoint is used verbatim, since a provider's key may ride in its path or
 * query. program is embedded for both presets, so only an endpoint alone must
 * set it. The USDC mint is never configured: it is read from the program's
 * Config. Each rail refuses the other's fields, so a Solana setting without
 * the rail fails rather than paying on Algorand mainnet.
 */
export interface Network {
    /** Absent is algorand. */
    rail?: Rail
    network?: NetworkName | SolanaClusterName
    algodEndpoint?: string
    algodToken?: string
    escrowAppId?: bigint
    /** The Solana cluster's JSON-RPC endpoint, overriding the preset's. */
    rpcEndpoint?: string
    /** The zs_escrow program id, base58; absent takes the preset's. */
    program?: string
}

export interface ResolvedNetwork {
    rail: Rail
    /** Empty when the chain was named only by its endpoint. */
    network: NetworkName | SolanaClusterName | ''
    /**
     * The network key names. On Algorand it follows the app id rather than
     * the name the config used; on Solana it is the cluster, or custom (see
     * resolveNetwork).
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
    /** The Algorand rail's; empty or 0n on Solana. */
    algodEndpoint: string
    algodToken: string
    escrowAppId: bigint
    /** The Solana rail's; empty on Algorand. */
    rpcEndpoint: string
    program: string
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

/**
 * A free-credit issuer: its Ed25519 public key as standard base64 (`parseIssuerKey` in
 * `@txnlab/zs-proto/freecredit` reads it), and the base URL it serves the issue wire on,
 * empty when the host supplies the transport. `loopbackOnly` marks an issuer whose private
 * key is public, which a node trusts only on a loopback RPC (Go's
 * `zsescrow.TrustedFreeCreditIssuers`).
 */
export interface FreeCreditIssuer {
    key: string
    url: string
    loopbackOnly: boolean
}

// The localnet issuer, whose private half is committed beside Go's stub node
// (go/internal/solanastub/freecredit_localnet_issuer.pem, and again in
// testdata/free_credit_vectors.json) so the end-to-end tests can make credits.
// It guards nothing.
const LOCALNET_FREE_CREDIT_ISSUER = 'n5/pE/SvxojCjN2WSMQJEU45KVij7zyjY3Fc7d36xjw='

// A localnet started by `make localnet` in zerosignal-contracts' solana/ loads
// the program's default build. Devnet has no issuer until ZeroSignal's key is
// made.
const solanaPresets: Record<SolanaClusterName, { rpcEndpoint: string; program: string; freeCreditIssuers: readonly FreeCreditIssuer[] }> = {
    devnet: { rpcEndpoint: 'https://api.devnet.solana.com', program: DEVNET_PROGRAM_ID, freeCreditIssuers: [] },
    localnet: {
        rpcEndpoint: 'http://127.0.0.1:8899',
        program: PROGRAM_ID,
        freeCreditIssuers: [{ key: LOCALNET_FREE_CREDIT_ISSUER, url: '', loopbackOnly: true }],
    },
}

/** A cluster preset's default free-credit issuers, a fresh copy; undefined for a name that is no preset. */
export function solanaClusterFreeCreditIssuers(name: string): FreeCreditIssuer[] | undefined {
    const key = name.toLowerCase()
    if (!Object.hasOwn(solanaPresets, key)) return undefined
    return solanaPresets[key as SolanaClusterName].freeCreditIssuers.map((i) => ({ ...i }))
}

/** The Solana presets, in the order Go lists them. */
export const solanaClusterNames: readonly SolanaClusterName[] = ['devnet', 'localnet']

export const mainnet = (): Network => ({ network: 'mainnet' })
export const testnet = (): Network => ({ network: 'testnet' })
export const localnet = (): Network => ({ network: 'localnet' })
export const solanaDevnet = (): Network => ({ rail: 'solana', network: 'devnet' })
export const solanaLocalnet = (): Network => ({ rail: 'solana', network: 'localnet' })

/**
 * resolveNetwork applies the preset and the overrides, or throws a ZsError.
 *
 * The label in key is the preset an app id belongs to, so a config naming
 * mainnet and one naming only its endpoint share state. Any other app id takes
 * the network the config names, since app ids are per network and testnet's
 * app 42 is not mainnet's. Only an endpoint alone is "custom", which splits
 * that config's state from the same deployment named as localnet; the cost is
 * rows left under the other key, not rows lost.
 *
 * On Solana the label is the cluster the config names, or "custom" for an
 * endpoint alone: a localnet can load any build at any id, so unlike an app id
 * a program id says nothing about which chain it is on.
 */
export function resolveNetwork(n: Network = {}): ResolvedNetwork {
    const rail = n.rail ?? 'algorand'
    if (rail === 'solana') return resolveSolana(n)
    if (rail !== 'algorand') {
        throw configError(`Network.rail ${String(rail)} is not supported`)
    }
    // || rather than !== undefined: an empty string is unset in Go, where it is the zero value.
    if (n.rpcEndpoint || n.program) {
        throw configError("Network.rpcEndpoint and Network.program are the Solana rail's; set Network.rail to solana")
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
        rpcEndpoint: '',
        program: '',
        feeSink: p?.feeSink ?? '',
        warnings,
    }
}

function resolveSolana(n: Network): ResolvedNetwork {
    if (n.algodEndpoint || n.algodToken || n.escrowAppId) {
        throw configError("Network.algodEndpoint, algodToken and escrowAppId are the Algorand rail's; a Solana Network sets rpcEndpoint and program")
    }
    // Lowered but not trimmed, as on Algorand.
    const name = n.network?.toLowerCase() ?? ''
    const rpcEndpoint = n.rpcEndpoint ?? ''
    if (name === '' && rpcEndpoint === '') {
        throw configError('Network.network or rpcEndpoint is required on the Solana rail')
    }
    if (name !== '' && !Object.hasOwn(solanaPresets, name)) {
        throw configError(
            `network must be one of ${solanaClusterNames.join('|')} (case-insensitive) on the Solana rail, got ${JSON.stringify(n.network)}`,
        )
    }
    const p = name === '' ? undefined : solanaPresets[name as SolanaClusterName]
    const warnings: string[] = []
    let program = n.program ?? ''
    if (program !== '') {
        let key: Uint8Array
        try {
            key = publicKeyBytes(program)
        } catch {
            throw configError(`Network.program ${JSON.stringify(program)} is not a Solana public key`)
        }
        // The all-zero key is Go's zero Program, which reads as unset there.
        if (key.every((b) => b === 0)) program = ''
    }
    if (program === '') {
        program = p?.program ?? ''
        if (p && rpcEndpoint !== '' && rpcEndpoint !== p.rpcEndpoint) {
            warnings.push(
                `Network.rpcEndpoint overrides the ${name} preset but the program is still that preset's (${program}); set Network.program if the endpoint is another cluster`,
            )
        }
    }
    if (program === '') {
        throw configError('Network.program is required for this network')
    }
    const label = name === '' ? 'custom' : name
    return {
        rail: 'solana',
        network: name as SolanaClusterName | '',
        label,
        key: `solana-${label}-${program}`,
        legacyKey: '',
        algodEndpoint: '',
        algodToken: '',
        escrowAppId: 0n,
        rpcEndpoint: rpcEndpoint || (p?.rpcEndpoint ?? ''),
        program,
        feeSink: '',
        warnings,
    }
}

/**
 * isLocal reports whether d is a development chain on this machine: the
 * localnet preset, reached at a loopback endpoint, as Go's Deployment.Local.
 * Nothing there is real money and its nodes run on this machine, so a payer's
 * defaults loosen (Config.privacy, Config.allowPrivateHosts). The endpoint
 * check keeps a config that names localnet but points at another chain from
 * loosening them: a program id says nothing about the chain (the localnet
 * preset's is deployed on devnet too).
 */
export function isLocal(d: ResolvedNetwork): boolean {
    if (d.label !== 'localnet') return false
    return loopbackEndpoint(d.rail === 'solana' ? d.rpcEndpoint : d.algodEndpoint)
}

/** loopbackEndpoint is whether endpoint names this machine, as Go's zsescrow.LoopbackEndpoint. */
export function loopbackEndpoint(endpoint: string): boolean {
    try {
        new URL(endpoint)
    } catch {
        return false
    }
    // The host as written, not WHATWG's hostname: that rewrites 127.1,
    // 0x7f000001 and a long IPv6 form into canonical addresses, which Go's
    // URL.Hostname and net.ParseIP leave as they are.
    const host = writtenHost(endpoint).toLowerCase()
    return host === 'localhost' || isLoopbackAddress(host)
}

/** writtenHost is endpoint's host as Go's URL.Hostname reads it: no userinfo, port or IPv6 brackets. */
function writtenHost(endpoint: string): string {
    let authority = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#]*)/.exec(endpoint)?.[1] ?? ''
    authority = authority.slice(authority.lastIndexOf('@') + 1)
    if (authority.startsWith('[')) {
        const end = authority.indexOf(']')
        return end < 0 ? '' : authority.slice(1, end)
    }
    const colon = authority.indexOf(':')
    return colon < 0 ? authority : authority.slice(0, colon)
}

/** The public chains by genesis hash, in each rail's usual encoding: Go's publicGenesis. */
const publicGenesis: Record<Rail, Record<string, string>> = {
    algorand: {
        'wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=': 'mainnet',
        'SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=': 'testnet',
        'mFgazF+2uRS1tMiL9dsj01hJGySEmPN28B/TjjvpVW0=': 'betanet',
    },
    solana: {
        '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d': 'mainnet-beta',
        '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY': 'testnet',
        EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG: 'devnet',
    },
}

/**
 * publicChain names the public chain whose genesis hash genesis is, or ''
 * for any other: Go's PublicChain. isLocal reads only a URL, and a loopback
 * URL can be a tunnel or a forwarder to a public chain, so a payer whose
 * defaults isLocal loosened checks the chain itself before it trusts them.
 */
export function publicChain(rail: Rail, genesis: Uint8Array): string {
    if (rail === 'solana') return genesis.length === 32 ? (publicGenesis.solana[encodeBase58(genesis)] ?? '') : ''
    return publicGenesis.algorand[scureBase64.encode(genesis)] ?? ''
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
