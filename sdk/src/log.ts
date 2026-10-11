/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Internal: not exported from the package.

import type { LogAttrs, Logger } from './ports.js'

/**
 * quietLogger is log with each call's throw dropped. Background work logs
 * through it, so a host logger that throws can't change what the work does.
 */
export function quietLogger(log: Logger): Logger {
    const quiet =
        (fn: (msg: string, attrs?: LogAttrs) => void) =>
        (msg: string, attrs?: LogAttrs): void => {
            try {
                fn.call(log, msg, attrs)
            } catch {}
        }
    return { debug: quiet(log.debug), info: quiet(log.info), warn: quiet(log.warn), error: quiet(log.error) }
}
