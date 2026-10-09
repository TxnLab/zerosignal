/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { fileURLToPath } from 'node:url'

import { defineConfig } from 'vitest/config'

export default defineConfig({
    // package.json's "imports" maps #default-fetch into dist; the tests run on
    // source, and in Node, so they take the Node build from src.
    resolve: {
        alias: {
            '#default-fetch': fileURLToPath(new URL('./src/node/default-fetch.ts', import.meta.url)),
        },
    },
    test: {
        include: ['test/**/*.test.ts'],
    },
})
