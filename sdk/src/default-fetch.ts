/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// #default-fetch is the fetch a Config without one gets. package.json's
// "imports" picks the build: under the "node" condition, node/default-fetch.ts,
// which refuses private addresses as Go's SDK does; anywhere else this one, the
// runtime's own fetch behind hostguard.ts's check of the URL's host. A browser
// can't resolve a name, so a public name that resolves to a private address
// gets past it there, as does a redirect from a public node to a private one,
// since the runtime follows it without asking; the literal shapes an operator
// can register do not. Refusing redirects outright would close the second at
// the price of a node behind an http-to-https redirect, which Go follows.
//
// The check sits on the fetch, as Go's sits on the dial, so every request the
// SDK makes to a node (a discovery probe, a relay hop, a reserve, the sealed
// request) is refused alike, and a private node reads as unreachable rather
// than vanishing from the chain read.

import { isBlockedOperatorUrl, PrivateTargetError } from './hostguard.js'
import type { Fetch } from './ports.js'

export function defaultFetch(allowPrivateHosts: boolean): Fetch | undefined {
    if (typeof globalThis.fetch !== 'function') return undefined
    const f = globalThis.fetch.bind(globalThis)
    if (allowPrivateHosts) return f
    return (input, init) => {
        // String() rather than instanceof URL, which a URL from another realm fails.
        const url = typeof input === 'object' && 'url' in input ? input.url : String(input)
        if (isBlockedOperatorUrl(url)) {
            let host = url
            try {
                host = new URL(url).hostname
            } catch {
                // Unparseable is blocked too; name it as given.
            }
            return Promise.reject(new PrivateTargetError(host, [host]))
        }
        return f(input, init)
    }
}
