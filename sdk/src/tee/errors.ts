/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The chain step's three non-verdict outcomes. Mirrors ErrCollateralUnavailable,
// ErrStaleCollateralRejected and ErrNoUsableCarriedCollateral in
// proto/go/zs/tee. They are classes rather than one error with a code because
// DstackVerifier branches on them, and the branch decides whether the node's
// own collateral may be consulted.

/**
 * Intel's collateral could not be obtained: OUR dependency failed, which says
 * nothing about the node. The only outcome that earns the node-carried
 * fallback.
 */
export class CollateralUnavailableError extends Error {
    constructor(cause: unknown) {
        super(`tee: Intel collateral unavailable: ${String(cause)}`, { cause })
        this.name = 'CollateralUnavailableError'
    }
}

/**
 * The quote was refused by collateral the verifier served from its own cache
 * because Intel was unreachable. A verdict was reached, so it must not fall
 * through to the node's collateral: that would trade a signed document of a
 * vintage we chose for one the operator chose. Reported as
 * collateral_unreachable, because the refusal cannot be attributed (the node's
 * evidence, or our aging document), and blaming the node accuses the whole
 * fleet during one outage.
 */
export class StaleCollateralRejectedError extends Error {
    /** outage is why our aging document was used; rejected is what it said. */
    constructor(outage: unknown, rejected?: unknown) {
        const verdict = rejected === undefined ? 'on an earlier attempt' : String(rejected)
        super(
            `tee: quote refused by cached Intel collateral: ${verdict} (Intel was unreachable: ${String(outage)})`,
            { cause: rejected ?? outage },
        )
        this.name = 'StaleCollateralRejectedError'
    }
}

/** The bundle carries no collateral the verifier will fall back to. */
export class NoUsableCarriedCollateralError extends Error {
    constructor(reason: string) {
        super(`tee: no usable node-carried collateral: ${reason}`)
        this.name = 'NoUsableCarriedCollateralError'
    }
}
