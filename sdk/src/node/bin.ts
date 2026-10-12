#!/usr/bin/env node
/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { main } from './cli.js'

process.exitCode = await main(process.argv.slice(2))
