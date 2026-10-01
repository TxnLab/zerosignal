/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Ed25519 seam. We use @noble/ed25519 — the standalone, audited
// ~300-line implementation — rather than @noble/curves/ed25519. It has
// a far smaller attack surface, but to stay minimal it leaves the
// SHA-512 dependency for the caller to wire in before the sync
// sign / verify / getPublicKey API can be used. Do that once here, as a
// module side effect, and re-export `ed25519` so every callsite gets a
// ready-to-use namespace. Anything that touches ed25519 must import it
// from this module, never directly from '@noble/ed25519'.

import { sha512 } from '@noble/hashes/sha2.js'
import * as ed25519 from '@noble/ed25519'

import { concatBytes } from './bytes.js'

// Enable the sync code paths (getPublicKey / sign / verify). The setter
// is idempotent — only the first assignment takes — so importing this
// module any number of times is safe.
ed25519.etc.sha512Sync = (...messages: Uint8Array[]): Uint8Array => sha512(concatBytes(...messages))

export { ed25519 }
