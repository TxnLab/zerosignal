/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Fetch } from './ports.js'

/**
 * withHeaderBackstop gives up on a request whose response headers haven't
 * come within ms, as Go's ResponseHeaderTimeout does; a fetch otherwise waits
 * forever. It rejects with a TimeoutError on a signal of its own, so the
 * caller's is still unaborted, and the body that follows the headers has no
 * bound from it.
 *
 * Go's clock starts once the request is written; a fetch can't see that, so
 * this one starts at the call and also counts the connection and the upload.
 */
export function withHeaderBackstop(f: Fetch, ms: number): Fetch {
    return (async (input: RequestInfo | URL, init?: RequestInit) => {
        const backstop = new AbortController()
        const timer = setTimeout(
            () => backstop.abort(new DOMException('timeout awaiting response headers', 'TimeoutError')),
            ms,
        )
        // An init signal replaces a Request's own, so both are kept.
        const own = [input instanceof Request ? input.signal : undefined, init?.signal ?? undefined].filter(
            (s): s is AbortSignal => s !== undefined,
        )
        try {
            return await f(input, { ...init, signal: AbortSignal.any([...own, backstop.signal]) })
        } finally {
            clearTimeout(timer)
        }
    }) as Fetch
}
