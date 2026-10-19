/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// GENERATED from proto/go/attest/releases.go and osimages.go. Do not edit.
//
// The Go lists are the single source. Regenerate with:
//   cd proto/go && go test ./attest -run TestTrustListTwinVectors -update-trust-lists
//
// Each function returns a fresh array, as the Go functions return a fresh
// slice: callers append to these when they build a policy, and a shared backing
// array would let one embedder's change reach the next.

export function trustedComposeSkeletons(): string[] {
    return [
        'ae96010a910e273e7884849eed31f347ef578f971ec2d8054becd02106242572',
        '2e4b9acc49e6daef45fb071a3a396e0d9a528fac15b9ea1bdd21e62335f59278',
        'ea8af51f03b9334a13f2ffd6db3aa09993776afc40c1b7bb2955a441157614d4',
        '62ed4839c902ac52a11ae8a5d0cf3e1e7899f85f249215d41a9d97c600b3c68b',
        '965467d015d5c27cde5b2573f8cecf67f6637cec79c28bb0afe54804b2c1bb5f',
        '6ec023cf3ec32ccdc4a00242bf76458174ea46c54f56c11d1a3fc2625f74a1bb',
        '42febe5c21352af69c14ffeed4620442d8856c72c5e5d3cb94ccd3d8b5115514',
        '7bafa7df128c1c176c00f9bc20c2e079931596b782167087ca3888cddcde3b80',
    ]
}

export function trustedNodeImages(): string[] {
    return [
        'ghcr.io/txnlab/zs-node@sha256:e9b6c927265197ce8bcd9234d852ab2d4ad8f2166434487835260cc7a519baaf',
        'ghcr.io/txnlab/zs-node@sha256:5d6062da1ba20913d06c187bb789eeb0d77759efee71fc68d27f6638e9aba757',
        'ghcr.io/txnlab/zs-node@sha256:3fc0c4f37fb2bfb0b7f50889f2a458047adab3a251352c5fb7f222f12de12b2c',
        'ghcr.io/txnlab/zs-node@sha256:878292a99694f1c5a882b732eaa19a71c76abefeccb4f1f159ae324489dfff62',
        'ghcr.io/txnlab/zs-node@sha256:19f2fc41c5407a92b8fe7d28084b74160b18755219a5404e57ad232f853def01',
        'ghcr.io/txnlab/zs-node@sha256:048fa6936e638286821dec7485b6faa39c965d71e9b8df550c20f71e2ab950a9',
        'ghcr.io/txnlab/zs-node@sha256:87ab8093d7a516a8a39dd29c31c8c05c03a4863d1ddbf4059598f2937012ceeb',
        'ghcr.io/txnlab/zs-node@sha256:41fefcfefd0d235226d22bd75d11a743b0d13d706191b48a71fef889343a50c9',
        'ghcr.io/txnlab/zs-node@sha256:6127236d703cc36dc541d8e8bbe0ec86cabf01204d9af78af334c2370f17bfd3',
        'ghcr.io/txnlab/zs-node@sha256:d3512188c73fae0bc68764e6be580cfd970701318098a83ae1dac521f6669243',
        'ghcr.io/txnlab/zs-node@sha256:3069cc0ee3cdfdf249172147eea274de456f033e7d7d74f88cefb58b466d0f8e',
        'ghcr.io/txnlab/zs-node@sha256:aa7cb1b7bb8514e0c15dfacfdef4ec409f7ff7f7356b28beb2fbbfa2a91d6a99',
        'ghcr.io/txnlab/zs-node@sha256:c121377681c75c6b75fc896c9614896294f2e0498a7d06a8317320ca0c9f2815',
        'ghcr.io/txnlab/zs-node@sha256:431196b2d5310556a696eeb344ee4f8f617124c82a30f3a01942a20d1ae306ae',
        'ghcr.io/txnlab/zs-node@sha256:ccac4239e39f9a9dbfe3c4a82a17210f63128ebfd748bde92bd73dac32708811',
        'ghcr.io/txnlab/zs-node@sha256:c8b5247c6f17517c6629496dade91beb31362a36c9495734a1da18cd45be3a50',
    ]
}

export function trustedDstackOSImages(): string[] {
    return [
        'bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033',
        '8db40cb23008d6213668b5816702d100b37b859a8a5bfd18d938ae3a1b3715bd',
        '91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829',
        'ec43cb8c5e04b6bb6c53b33b16076a01d83d01f7f4b703f2f78a0d947d6247e6',
    ]
}
