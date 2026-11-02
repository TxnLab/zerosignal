/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The check behind the local defaults, mirroring proto/go/zs/local.go.

import type algosdk from 'algosdk'
import { decodeBase58 } from '@txnlab/zs-proto/solana'

import type { ResolvedConfig } from './config.js'
import { suggestedParams } from './escrow/algod.js'
import { configError } from './errors.js'
import { publicChain } from './network.js'
import type { SolanaRpc } from './solana/rpc.js'

/** Go's escrowConfigTimeout, which bounds its genesis read. */
const GENESIS_READ_TIMEOUT_MS = 10_000

/** A read of the genesis hash the chain behind a Client's endpoint serves. */
export type GenesisRead = (signal: AbortSignal) => Promise<Uint8Array>

/**
 * checkLocalChain refuses a config whose local defaults loosened privacy or
 * allowPrivateHosts when the chain behind its loopback endpoint is a public
 * one: through a tunnel or a forwarder, discovery would list that chain's
 * operators, and the payer would show them its address and fetch whatever
 * private URL one registered. A read that fails fails the check, since the
 * defaults were loosened on the assumption it would pass. Set values were the
 * caller's choice and are not checked.
 */
export async function checkLocalChain(cfg: ResolvedConfig, read: GenesisRead, signal?: AbortSignal): Promise<void> {
    if (!cfg.localDefaults) return
    const timeout = AbortSignal.timeout(GENESIS_READ_TIMEOUT_MS)
    let genesis: Uint8Array
    try {
        genesis = await read(signal ? AbortSignal.any([signal, timeout]) : timeout)
    } catch (err) {
        if (signal?.aborted) throw err
        throw new Error(`zs: read genesis hash: ${err instanceof Error ? err.message : String(err)}`, { cause: err })
    }
    const name = publicChain(cfg.network.rail, genesis)
    if (name) throw configError(`the localnet endpoint serves ${name}; name that network, or set privacy and allowPrivateHosts`)
}

export function algodGenesis(algod: algosdk.Algodv2): GenesisRead {
    return async (signal) => {
        const sp = await suggestedParams(algod, GENESIS_READ_TIMEOUT_MS, signal)
        if (!sp.genesisHash) throw new Error('algod returned none')
        return sp.genesisHash
    }
}

export function solanaGenesis(rpc: Pick<SolanaRpc, 'getGenesisHash'>): GenesisRead {
    return async (signal) => decodeBase58(await rpc.getGenesisHash({ signal }), 32)
}
