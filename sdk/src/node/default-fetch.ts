/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The "node" build of #default-fetch: Go's default, a fetch that refuses
// private addresses unless allowPrivateHosts. See ../default-fetch.ts, whose
// declarations both builds publish, so this one must fit them.

import type { defaultFetch as shared } from '../default-fetch.js'
import { nodeFetch } from './fetch.js'

export const defaultFetch = ((allowPrivateHosts) => nodeFetch({ allowPrivateHosts })) satisfies typeof shared
