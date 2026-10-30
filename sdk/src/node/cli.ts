/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The zerosignal command. bin.ts runs it; it is apart so a test can drive it.

import { parseArgs } from 'node:util'

import { isValidAddress } from 'algosdk'

import { diagnose, type DoctorReport, type DoctorStatus } from '../doctor.js'
import { ZsError } from '../errors.js'
import type { Network, NetworkName, Rail, SolanaClusterName } from '../network.js'

export const USAGE = `usage: zerosignal doctor --address <address> [options]

Checks, without signing anything, what a payer address needs before a request
can succeed: the chain, the escrow, the account's fee coin and USDC, the
prepaid ticket pool, and the nodes that would serve it.

options:
  --rail <rail>          algorand (default) or solana
  --network <name>       on Algorand mainnet (default), testnet or localnet;
                         on Solana devnet or localnet, with no default
  --direct               probe nodes directly instead of through relays
                         (the default on a localnet at a loopback endpoint)
  --allow-staging        count staging nodes as able to serve
  --allow-private-hosts  probe nodes on private addresses (a local fleet; the
                         default on a localnet at a loopback endpoint)
  --json                 print the report as JSON

Algorand options:
  --algod-url <url>      an algod other than the network's preset
  --algod-token <token>  that algod's API token
  --escrow-app-id <id>   the escrow app, for localnet or a private chain

Solana options (each needs --rail solana):
  --rpc-url <url>        a JSON-RPC endpoint other than the cluster's preset;
                         without --network it needs --program
  --program <id>         the zs_escrow program id, base58

Each rail refuses the other's options.

Exits 0 when no check fails, 1 when one does, 2 on a usage error, and 3 when
the doctor itself fails.
`

const MARK: Record<DoctorStatus, string> = { pass: 'ok  ', warn: 'warn', fail: 'FAIL', skip: 'skip' }

interface Out {
    write(s: string): unknown
}

const STRING_FLAGS = ['address', 'rail', 'network', 'algod-url', 'algod-token', 'escrow-app-id', 'rpc-url', 'program'] as const

/** main runs the command line and returns the exit code; see USAGE. run is diagnose, apart for a test. */
export async function main(
    argv: readonly string[],
    out: Out = process.stdout,
    err: Out = process.stderr,
    run: typeof diagnose = diagnose,
): Promise<number> {
    let values
    let address: string
    try {
        const parsed = parseArgs({
            args: [...argv],
            allowPositionals: true,
            options: {
                address: { type: 'string' },
                rail: { type: 'string' },
                network: { type: 'string' },
                'algod-url': { type: 'string' },
                'algod-token': { type: 'string' },
                'escrow-app-id': { type: 'string' },
                'rpc-url': { type: 'string' },
                program: { type: 'string' },
                direct: { type: 'boolean' },
                'allow-staging': { type: 'boolean' },
                'allow-private-hosts': { type: 'boolean' },
                json: { type: 'boolean' },
                help: { type: 'boolean', short: 'h' },
            },
        })
        if (parsed.values.help) {
            out.write(USAGE)
            return 0
        }
        if (parsed.positionals.length !== 1 || parsed.positionals[0] !== 'doctor') throw new Error('expected the doctor command')
        // An empty value is most often an unset shell variable, and an empty
        // --network would otherwise read as mainnet.
        for (const f of STRING_FLAGS) {
            if (parsed.values[f] === '') throw new Error(`--${f} is empty`)
        }
        if (parsed.values.address === undefined) throw new Error('--address is required')
        const rail = parsed.values.rail
        if (rail !== undefined && rail !== 'algorand' && rail !== 'solana') throw new Error('--rail must be algorand or solana')
        const id = parsed.values['escrow-app-id']
        if (id !== undefined && !/^[1-9]\d*$/.test(id)) throw new Error('--escrow-app-id must be a positive number')
        values = parsed.values
        address = parsed.values.address
    } catch (e) {
        err.write(`zerosignal: ${message(e)}\n\n${USAGE}`)
        return 2
    }

    // resolveNetwork refuses one rail's fields on the other, so the flags pass
    // through as given and the cross-rail rules live in one place. --rail is
    // checked above as well, so a misspelled rail prints the usage.
    const network: Network = {}
    if (values.rail !== undefined) network.rail = values.rail as Rail
    if (values.network !== undefined) network.network = values.network as NetworkName | SolanaClusterName
    if (values['algod-url'] !== undefined) network.algodEndpoint = values['algod-url']
    if (values['algod-token'] !== undefined) network.algodToken = values['algod-token']
    if (values['escrow-app-id'] !== undefined) network.escrowAppId = BigInt(values['escrow-app-id'])
    if (values['rpc-url'] !== undefined) network.rpcEndpoint = values['rpc-url']
    if (values.program !== undefined) network.program = values.program

    let report: DoctorReport
    try {
        report = await run(
            {
                network,
                // Absent flags leave the settings to the network's defaults,
                // as a Client's config does.
                ...(values.direct && { privacy: 'direct' as const }),
                allowStaging: values['allow-staging'] ?? false,
                ...(values['allow-private-hosts'] !== undefined && { allowPrivateHosts: values['allow-private-hosts'] }),
            },
            address,
        )
    } catch (e) {
        if (e instanceof ZsError) {
            // Leaving --rail off is the likeliest mistake with a Solana address
            // or cluster, and the Algorand refusal it gets doesn't say so.
            const solanaHint =
                values.rail === undefined && (values.network?.toLowerCase() === 'devnet' || !isValidAddress(address))
                    ? ' (pass --rail solana for the Solana rail)'
                    : ''
            err.write(`zerosignal: ${e.message}${solanaHint}\n`)
            return 2
        }
        err.write(`zerosignal: the doctor failed: ${e instanceof Error && e.stack ? e.stack : message(e)}\n`)
        return 3
    }
    for (const w of report.warnings) err.write(`zerosignal: warning: ${w}\n`)
    if (values.json) {
        out.write(`${JSON.stringify(report, null, 2)}\n`)
    } else {
        out.write(`zerosignal doctor: ${report.address} on ${report.network || 'a private network'}\n`)
        const width = Math.max(...report.checks.map((c) => c.id.length))
        for (const c of report.checks) out.write(`  ${MARK[c.status]}  ${c.id.padEnd(width)}  ${c.message}\n`)
    }
    return report.failed ? 1 : 0
}

function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e)
}
