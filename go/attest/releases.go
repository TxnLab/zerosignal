/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

// TrustedComposeSkeletons and TrustedNodeImages are the published zs-node
// releases this build recognizes — the per-RELEASE half of the compose check,
// shipped so a payer verifies a released node out of the box rather than
// pasting values they have no way to derive by hand.
//
// THEY LIVE HERE so every payer gets them: zs-proxy seeds its config from them,
// and an SDK caller that sets no TEEVerifier gets tee.DefaultVerifier, which
// reads them. A copy in each consumer is how a payer ends up refusing a release
// the others accept.
//
// THE SAME VALUES LIVE IN TWO REPOS, AND NOTHING EXECUTABLE SPANS THEM. The
// skeleton digest is COMPUTED in zs-node's deploy/dstack package
// (ReleaseComposeSkeletonDigest, bound to the embedded compose by
// TestSkeletonDigestIsTheReleaseValue); this list is a COPY of it. Nothing
// compares the two — the release workflow only ever appends, so a value that
// drifts stays drifted, and between a compose edit in zs-node and the next tag
// they are legitimately out of step. A compose edited without a release entry
// here refuses every node running it, silently: the deploy succeeds, the quote
// verifies, and payers route elsewhere with nothing logged on the operator's
// side.
//
// proto/ts/src/attest/trust-lists.ts is not a third copy: it is GENERATED from
// this file (TestTrustListTwinVectors), and that test fails while it is stale.
//
// ENTRIES ARE APPENDED BY zs-node's release-allowlist.yml on every version
// tag, above the marker at the end of each literal, and the same pull request
// regenerates the TypeScript twin. It opens a pull request rather than pushing
// to the base branch, so the values arrive through a merge; only the copy-paste
// step is removed. A merge reaches payers only through a release here and
// the zs-proxy and client pin bumps.
//
// THAT IS A REVIEWED PATH ONLY WITH A RULESET on this repository's default
// branch requiring a reviewed pull request, with NO bypass for the GitHub App
// the workflow authenticates as. The App holds `contents: write` here, so a
// compromise of zs-node's Actions secrets is write access to this list, and the
// review is the only thing bounding it. It has to be an App: a fine-grained PAT
// acts as the user who minted it and inherits that user's admin bypass,
// exempting from review precisely the credential the review exists to contain.
// Adding the App to the bypass list undoes this, and nothing here can detect
// it. MEASURED 2026-10-11: the `main` ruleset requires 1 approving review and
// the App is not on its bypass list, so the App cannot merge its own pull
// request. Lowering required_approving_review_count to 0 would leave the
// required checks as all that bound it.
//
// To add one by hand, compute a release's values with
// `go run ./cmd/release-allowlist print -image <ref>` in the zs-node repo (the
// image ref is an input there, not something it derives), or read them off
// `zs-proxy tee inspect --file <that release's compose>`, then regenerate the
// twin with `go test ./attest -run TestTrustListTwinVectors -update-trust-lists`.
//
// THE TWO LISTS ARE SEPARATE BECAUSE THEY MOVE APART. A release that changes
// only the binary yields a new image digest and the SAME skeleton, since the
// image reference is one of the two spans lifted before hashing. Merging them
// into one entry would force a skeleton churn on every binary release.
//
// Fresh slices per call, as TrustedDstackOSImages returns: they land in config
// structs callers mutate.
func TrustedComposeSkeletons() []string {
	return []string{
		// node/deploy/dstack/docker-compose.yaml.example as published at
		// v0.19.0-alpha.4. Inserted by zs-node's release-allowlist workflow.
		"ae96010a910e273e7884849eed31f347ef578f971ec2d8054becd02106242572",
		// Simplified operator guidance in the measured compose.
		"2e4b9acc49e6daef45fb071a3a396e0d9a528fac15b9ea1bdd21e62335f59278",
		// node/deploy/dstack/docker-compose.yaml.example as published at
		// v0.19.1. Inserted by zs-node's release-allowlist workflow.
		"ea8af51f03b9334a13f2ffd6db3aa09993776afc40c1b7bb2955a441157614d4",
		// node/deploy/dstack/docker-compose.yaml.example as published at
		// v0.20.0. Inserted by zs-node's release-allowlist workflow.
		"62ed4839c902ac52a11ae8a5d0cf3e1e7899f85f249215d41a9d97c600b3c68b",
		// No GPU skeleton from before v0.23.0 belongs here: those composes pin
		// Kronk 1.32.3, which does not verify the llama.cpp library it loads
		// from an unmeasured volume. Do not re-add them, including via a manual
		// release-allowlist run against an older tag.
		//
		// node/deploy/dstack/docker-compose.gpu.yaml.example (sealed_local:
		// node + digest-pinned engine) as published at v0.23.0.
		"965467d015d5c27cde5b2573f8cecf67f6637cec79c28bb0afe54804b2c1bb5f",
		// node/deploy/dstack/docker-compose.yaml.example with the image-backend
		// and cloud-secret env NAMES added (NODE_IMAGE_LLM_OPENAI_API_KEY,
		// ZS_MNEMONIC_URLS). Staged by hand ahead of the release tag; the
		// release-allowlist workflow no-ops on a value already present.
		"6ec023cf3ec32ccdc4a00242bf76458174ea46c54f56c11d1a3fc2625f74a1bb",
		// node/deploy/dstack/docker-compose.gpu.yaml.example (sealed_local) with
		// the same two env NAMES added and the adjacent comment reworded — the
		// comments are inside the hashed text, so both moved this digest.
		"42febe5c21352af69c14ffeed4620442d8856c72c5e5d3cb94ccd3d8b5115514",
		// node/deploy/dstack/docker-compose.gpu.yaml.example (sealed_local) with
		// its comments reworded to describe the engine's library check without
		// version history. Staged by hand ahead of the release tag; the
		// release-allowlist workflow no-ops on a value already present.
		"7bafa7df128c1c176c00f9bc20c2e079931596b782167087ca3888cddcde3b80",
		// zs-node-release-list: compose-skeletons
		//
		// ^ ANCHOR, not decoration. zs-node's release-allowlist.yml inserts
		// new entries immediately ABOVE this line on every version tag.
		// Deleting it, duplicating it, or moving it into the other list all
		// FAIL that job rather than silently doing nothing — a `sed`-style
		// no-match would exit 0 and push an empty branch that reads as
		// "already current".
		//
		// The cross-list case is why the marker names its list rather than the
		// tool anchoring on the closing brace: an image reference written in
		// here is never equal to any skeleton digest, so every node running
		// that release is refused with nothing logged anywhere.
	}
}

// TrustedNodeImages holds published references VERBATIM, repository included,
// rather than bare digests: the repository half is what says these bytes are
// the ones CI published, not merely the right bytes served from somewhere else.
func TrustedNodeImages() []string {
	return []string{
		// v0.19.0-alpha.1 — the first tag carrying NODE_CONFIG_YAML, so the
		// first image the measured compose can actually run. Multi-arch index
		// digest, which is what a compose `image:` pins.
		"ghcr.io/txnlab/zs-node@sha256:e9b6c927265197ce8bcd9234d852ab2d4ad8f2166434487835260cc7a519baaf",
		// v0.19.0-alpha.4 — multi-arch index digest, which is what a compose `image:`
		// pins. Inserted by zs-node's release-allowlist workflow.
		"ghcr.io/txnlab/zs-node@sha256:5d6062da1ba20913d06c187bb789eeb0d77759efee71fc68d27f6638e9aba757",
		// v0.19.0 — multi-arch index digest, which is what a compose `image:`
		// pins. Inserted by zs-node's release-allowlist workflow.
		"ghcr.io/txnlab/zs-node@sha256:3fc0c4f37fb2bfb0b7f50889f2a458047adab3a251352c5fb7f222f12de12b2c",
		// v0.19.1 — multi-arch index digest, which is what a compose `image:`
		// pins. Inserted by zs-node's release-allowlist workflow.
		"ghcr.io/txnlab/zs-node@sha256:878292a99694f1c5a882b732eaa19a71c76abefeccb4f1f159ae324489dfff62",
		// v0.20.0 — multi-arch index digest, which is what a compose `image:`
		// pins. Inserted by zs-node's release-allowlist workflow.
		"ghcr.io/txnlab/zs-node@sha256:19f2fc41c5407a92b8fe7d28084b74160b18755219a5404e57ad232f853def01",
		// v0.21.0 — multi-arch index digest, which is what a compose `image:`
		// pins. Inserted by zs-node's release-allowlist workflow.
		"ghcr.io/txnlab/zs-node@sha256:048fa6936e638286821dec7485b6faa39c965d71e9b8df550c20f71e2ab950a9",
		// v0.21.1 — multi-arch index digest, which is what a compose `image:`
		// pins. Inserted by zs-node's release-allowlist workflow.
		"ghcr.io/txnlab/zs-node@sha256:87ab8093d7a516a8a39dd29c31c8c05c03a4863d1ddbf4059598f2937012ceeb",
		// v0.22.0 — multi-arch index digest, which is what a compose `image:`
		// pins. Inserted by zs-node's release-allowlist workflow.
		"ghcr.io/txnlab/zs-node@sha256:41fefcfefd0d235226d22bd75d11a743b0d13d706191b48a71fef889343a50c9",
		// v0.22.1 — multi-arch index digest, which is what a compose `image:`
		// pins. Inserted by zs-node's release-allowlist workflow.
		"ghcr.io/txnlab/zs-node@sha256:6127236d703cc36dc541d8e8bbe0ec86cabf01204d9af78af334c2370f17bfd3",
		// v0.23.0 — multi-arch index digest, which is what a compose `image:`
		// pins. Inserted by zs-node's release-allowlist workflow.
		"ghcr.io/txnlab/zs-node@sha256:d3512188c73fae0bc68764e6be580cfd970701318098a83ae1dac521f6669243",
		// v0.24.0 — multi-arch index digest, which is what a compose `image:`
		// pins. Inserted by zs-node's release-allowlist workflow.
		"ghcr.io/txnlab/zs-node@sha256:3069cc0ee3cdfdf249172147eea274de456f033e7d7d74f88cefb58b466d0f8e",
		// v0.25.0 — multi-arch index digest, which is what a compose `image:`
		// pins. Inserted by zs-node's release-allowlist workflow.
		"ghcr.io/txnlab/zs-node@sha256:aa7cb1b7bb8514e0c15dfacfdef4ec409f7ff7f7356b28beb2fbbfa2a91d6a99",
		// v0.26.0 — multi-arch index digest, which is what a compose `image:`
		// pins. Inserted by zs-node's release-allowlist workflow.
		"ghcr.io/txnlab/zs-node@sha256:c121377681c75c6b75fc896c9614896294f2e0498a7d06a8317320ca0c9f2815",
		// zs-node-release-list: node-images
		//
		// ^ ANCHOR — see the note on the skeleton list's marker above. This is
		// the list that moves on EVERY release, since a binary-only change
		// yields a new image digest and the same skeleton.
	}
}
