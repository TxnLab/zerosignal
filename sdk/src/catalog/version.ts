/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * restoredProtoVersion floors a protocol version read back from storage to
 * "<major>.0". What a node advertised last session says nothing about what it
 * runs now, and assuming too high a minor fails hard (a reserve sized for a
 * capability the node rolled back is refused after escrow opens), while too
 * low only forgoes the capability until the next probe. The major is kept, so
 * compatibility is unaffected. Go's minorFloor in persist.go, pinned by
 * testdata/persisted_proto_version_vectors.json.
 */
export function restoredProtoVersion(version: string): string {
    if (version === '') return ''
    const dot = version.indexOf('.')
    if (dot < 0 || dot === 0) return version
    return `${version.slice(0, dot)}.0`
}
