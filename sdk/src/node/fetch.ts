/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Node's fetch for dialing node-registered addresses, as Go's SDK dials them
// (zs Config.nodeHTTPClient over httpx's BlockPrivateTargets): unless
// allowPrivateHosts, no connection is made to a private address, whatever name
// led to it.
//
// The check runs inside the dial. Every name the socket resolves goes through
// guardedLookup, which drops the private addresses before the socket sees any,
// so the address judged is the address dialed and a rebind has no second
// resolution to slip into. Node never looks up a literal IP, so the connector
// judges those itself. Go's hook skips a refused address and dials the next;
// dropping it from the answer does the same.
//
// undici's own fetch rather than the global one: Node does not expose the
// Agent its fetch is built on, and a dispatcher from another undici is not
// guaranteed to fit it. Neither Agent reads HTTP_PROXY, as Go's SDK doesn't by
// default. It returns undici's Response, not the global class.
//
// Node only. Bun answers `import 'undici'` with a stand-in whose Agent is
// ignored, so there the guard would let every dial through; Deno is untested.
// nodeFetch refuses to build a guard in either, and package.json gives both the
// runtime's own fetch, as a browser gets.

import { lookup as dnsLookup, type LookupAddress, type LookupOptions } from 'node:dns'
import { isIP, type LookupFunction } from 'node:net'

import { Agent, buildConnector, fetch as undiciFetch, Request as UndiciRequest } from 'undici'

import { configError } from '../errors.js'
import type { Fetch } from '../ports.js'
import { isPrivateAddress } from '../privateip.js'

/** PrivateTargetError fails a dial to a private address: Go's httpx.ErrPrivateTarget. */
export class PrivateTargetError extends Error {
    override readonly name = 'PrivateTargetError'

    constructor(readonly host: string, readonly addresses: readonly string[]) {
        super(`refusing to dial private/loopback/link-local address: ${host}${addresses.length && addresses[0] !== host ? ` (${addresses.join(', ')})` : ''}`)
    }
}

type Resolve = (hostname: string, options: LookupOptions & { all: true }, callback: (err: NodeJS.ErrnoException | null, addresses: LookupAddress[]) => void) => void

/**
 * guardedLookup is a socket lookup that resolves through resolve and answers
 * only with the addresses isPrivateAddress allows, failing with a
 * PrivateTargetError when none are left.
 */
export function guardedLookup(resolve: Resolve = dnsLookup): LookupFunction {
    return (hostname, options, callback) => {
        resolve(hostname, { ...options, all: true }, (err, addresses) => {
            if (err) {
                callback(err, '')
                return
            }
            const allowed = addresses.filter((a) => !isPrivateAddress(a.address))
            const first = allowed[0]
            if (!first) {
                callback(
                    new PrivateTargetError(
                        hostname,
                        addresses.map((a) => a.address),
                    ),
                    '',
                )
                return
            }
            if (options.all) callback(null, allowed)
            else callback(null, first.address, first.family)
        })
    }
}

function guardedAgent(resolve?: Resolve): Agent {
    const connector = buildConnector({ lookup: guardedLookup(resolve) })
    return new Agent({
        connect: (opts, callback) => {
            if (isIP(opts.hostname) && isPrivateAddress(opts.hostname)) {
                callback(new PrivateTargetError(opts.hostname, [opts.hostname]), null)
                return
            }
            connector(opts, callback)
        },
    })
}

// Whether undici's Agent here is Node's, whose lookup the socket honours.
function guardsDials(): boolean {
    return process.versions.bun === undefined && !('Deno' in globalThis)
}

/** NodeFetchOptions configures nodeFetch. */
export interface NodeFetchOptions {
    /** Dial private addresses too. Development only, as Config.allowPrivateHosts. */
    allowPrivateHosts?: boolean
    /** @internal The resolver behind the guard; dns.lookup. */
    resolve?: Resolve
}

/**
 * nodeFetch is a fetch over its own connection pool that, unless
 * allowPrivateHosts, refuses to connect to a private address. A refused dial
 * rejects as fetch does on any connection failure, a TypeError whose cause is
 * the PrivateTargetError.
 */
export function nodeFetch(opts: NodeFetchOptions = {}): Fetch {
    if (!opts.allowPrivateHosts && !guardsDials()) {
        throw configError('nodeFetch guards dials only under Node; this runtime would let a private address through')
    }
    const dispatcher = opts.allowPrivateHosts ? new Agent() : guardedAgent(opts.resolve)
    return ((input: RequestInfo | URL, init?: RequestInit) => {
        // undici's fetch takes only its own Request class, and reads any other
        // object as a URL string.
        const req = typeof input === 'string' || input instanceof URL ? input : new UndiciRequest(input.url, input as never)
        return undiciFetch(req, { ...(init as object), dispatcher } as never)
    }) as Fetch
}
