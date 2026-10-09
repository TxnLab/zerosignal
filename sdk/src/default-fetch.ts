/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// #default-fetch is the fetch a Config without one gets. package.json's
// "imports" picks the build: under the "node" condition, node/default-fetch.ts,
// which refuses private addresses as Go's SDK does; anywhere else this one, the
// runtime's own fetch. A browser can't resolve a name, so there only
// hostguard.ts's check of the registered host applies.

import type { Fetch } from './ports.js'

export function defaultFetch(_allowPrivateHosts: boolean): Fetch | undefined {
    return typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : undefined
}
