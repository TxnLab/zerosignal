/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

// TrustedDstackOSImages are the PRODUCTION dstack guest images this build
// recognizes.
//
// IT LIVES HERE BECAUSE EVERY GO CONSUMER NEEDS THE SAME LIST AND NONE OF THEM
// CAN DERIVE IT. The proxy and the browser client appraise NODES with it; a
// node appraises its own ACI/1 UPSTREAM with it. Those are different questions
// about the same fleet of guest images, and two Go copies reaching different
// verdicts on identical evidence is the failure the shared attest module
// exists to prevent. `zs-proxy`'s defaultTrustedOSImages delegates here;
// client/src/operators/tee-allowlist.ts is the one remaining hand-copy, kept
// honest by the shared policy vector.
//
// A DEV IMAGE MUST NEVER BE ADDED. This list is the only thing that catches a
// quote taken on `dstack-dev-*`, where every other check in the chain passes
// identically while the platform's hardening guarantees do not hold — and
// `phala deploy` picked a dev image on its own when `--image` was omitted
// (measured 2026-08-25), so it is a mistake that ships rather than a
// hypothetical.
//
// THIS VALUE IS ON NO AUTOMATION. It moves when Phala ships a guest image, and
// nothing anywhere notices a stale entry: the deploy succeeds, the quote
// verifies, and payers route elsewhere with nothing logged. Re-read it from
// `phala os-images` and update the other two copies in the same change:
// client/src/operators/tee-allowlist.ts (TRUSTED_OS_IMAGES — the browser's own,
// since proto/ts holds no copy) and node/internal/tee/dstackprobe.sh's
// ds_os_image_hash. The first of those is pinned against this list through
// testdata/compose_vectors.json's shared_policy.trusted_os_images; the shell
// script is pinned by nothing.
//
// Returns a fresh slice per call: it lands in config structs callers mutate,
// and a shared backing array would let one embedder's append be observed by
// the next.
func TrustedDstackOSImages() []string {
	return []string{
		// dstack-0.5.9. The same digest pinned by
		// proto/testdata/attest_vectors.json and the dstack verifier's
		// tests, so all of them move together or a test goes red.
		"bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033",

		// dstack-nvidia-0.5.9 — the GPU line's PRODUCTION image, read
		// off `phala os-images` on 2026-09-02 (DEV column: no). Present
		// because the CPU digest alone refused every node on a Phala
		// GPU: not "ran on a dev image", but "ran on an image this build
		// has never heard of" — the same refusal with a misleading
		// cause.
		//
		// What pins this digest in the DEFAULT suite is weaker than it
		// looks and worth knowing exactly (a live GPU capture now exists,
		// but it is not in the corpus and no test reads it): it is
		// carried in testdata/compose_vectors.json, so a
		// wrong digit goes red in TestComposeVectors and in the client's
		// tee-allowlist test — as a DISAGREEMENT between two copies, not
		// as a wrong value. Either copy satisfies them, so the red says
		// "these two differ", never "this one is wrong", and a digit
		// wrong in all four copies is invisible there.
		//
		// TestLive_TrustedOSImages_MatchTheVendorRelease is what closes
		// that (`-tags osimageslive`, out of the default suite because it
		// fetches from GitHub). Run it when adding or changing an entry.
		//
		// CONFIRMED AGAINST THE VENDOR 2026-09-25, which is the only
		// check that can say the value is right rather than merely
		// consistent between our own copies. Verified here, not taken on
		// report: digest.txt inside dstack-nvidia-0.5.9.tar.gz on the
		// Dstack-TEE/meta-dstack v0.5.9 release is this exact string,
		// AND it equals sha256(sha256sum.txt) byte for byte.
		//
		// That second equality is what makes the value meaningful rather
		// than just a published constant, because sha256sum.txt commits
		// to ovmf.fd, bzImage, initramfs.cpio.gz and metadata.json — and
		// metadata.json carries the dm-verity rootfs_hash. So the one
		// number dstack measures transitively fixes the firmware, the
		// kernel, the initramfs and every byte of the rootfs. ovmf.fd and
		// bzImage were re-hashed here and match their listed entries.
		//
		// DONE 2026-09-25 ON THIS LINE TOO, so the paragraph that used
		// to say "no GPU capture exists" is retired rather than left to
		// rot. A GPU CVM serving two of Phala's models publishes its own
		// quote at
		// `https://qwen3-8-27b-uncensored.use1.phala.com/evidences/quote.json`,
		// and it carries this exact digest as its `os-image-hash` — the
		// first evidence that the value is in service and not merely
		// published. RTMR0, RTMR1 and RTMR2 replay from its event log
		// exactly, and
		//
		//	sha384(initramfs.cpio.gz) == that quote's RTMR2 initrd event
		//
		// so the DOWNLOADED artifact is the one that BOOTED — the check
		// this comment used to say it could not make. The initramfs is
		// byte-shared with the CPU image (sha256 4662c4f0…), so this pins
		// the boot chain; the GPU rootfs is still pinned only
		// transitively, through sha256sum.txt → metadata.json →
		// dm-verity root hash. RTMR3 on that capture replays at no
		// prefix — its quote and its event log are from different boots —
		// which is why the binding above rests on RTMR2 and not on the
		// os-image-hash EVENT. Written up as
		// plans/future/tee/phala-revalidation-2026-09-25.md § 12.4; § 9.4
		// is the same procedure on the CPU image.
		//
		// Re-checking the digest needs no 510MB download; both text files
		// sit early in the tar, so a truncated stream is enough:
		//
		//	curl -sSL -H 'Range: bytes=0-31000000' \
		//	  https://github.com/Dstack-TEE/meta-dstack/releases/download/v0.5.9/dstack-nvidia-0.5.9.tar.gz \
		//	  | gunzip 2>/dev/null | tar -xf - -C <dir> 2>/dev/null; \
		//	  cat <dir>/dstack-nvidia-0.5.9/digest.txt; \
		//	  sha256sum <dir>/dstack-nvidia-0.5.9/sha256sum.txt
		"806a352e16175d90568de97dff563f31f680239e6b90e9b5b2e9141d0955b0d9",
	}
}

// OSImagesWithoutSSHDaemon are the guest images whose filesystems were
// enumerated and found to contain NO way to consume an authorized_keys file.
// It is the set ComposePolicy.RootBackdoorSafeOSImages is built from.
//
// SEPARATE FROM TrustedDstackOSImages AND DELIBERATELY SHORTER. Trusting an
// image says its measurement maps to a published production artifact; naming it
// here says someone opened it and looked. The second does not follow from the
// first, and conflating them is what let a root-backdoor concession apply to an
// image nobody had checked — see ComposePolicy.RootBackdoorSafeOSImages for what
// that cost. A new dstack release joins the list above as soon as its digest is
// confirmed against the vendor; it joins THIS list only after the scan.
//
// dstack-0.5.9, scanned 2026-09-25. Absent from the squashfs rootfs (2081
// distinct names recovered from the directory table) and from the initramfs (638
// entries): sshd, ssh, openssh, dropbear, tinyssh, ssh-keygen, ssh-agent,
// sshd_config, authorized_keys, host keys — and also agetty, getty, login and
// sudo, so there is no console login path either. The only matches for "ssh"
// anywhere are libssh.so.4, cryptsetup-ssh and libcryptsetup-token-ssh.so:
// systemd-cryptenroll's SSH-token plugin for unlocking a LUKS volume via an
// ssh-agent, which is a client library and not a daemon.
//
// WHY A BYTE SCAN IS NOT THE PROCEDURE. The first attempt grepped the rootfs
// image for those names and found zero hits — including for systemd, bash and
// busybox, which are certainly present. squashfs keeps filenames in
// zlib-compressed metadata blocks, so a raw scan reports a confident false
// clean. The procedure is to parse the directory table and ASSERT THE CONTROL
// NAMES PRESENT; ten were, which is the only reason the SSH result means
// anything. Written up as § 9.2 and § 9.4 step 5 of
// plans/future/tee/phala-revalidation-2026-09-25.md.
//
// dstack-nvidia-0.5.9 IS NOT HERE, and its absence is a fact rather than an
// oversight: it ships the identical initramfs (sha256 4662c4f0…, so that half
// carries over) but a different, larger rootfs (497MB) which has not been
// enumerated. A node on the GPU line therefore gets the STRICT root-backdoor
// rule. That is the correct default and the honest one — add it once the scan is
// run, not before.
func OSImagesWithoutSSHDaemon() []string {
	return []string{
		"bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033",
	}
}
