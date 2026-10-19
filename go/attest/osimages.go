/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

// TrustedDstackOSImages are the PRODUCTION dstack guest images this build
// recognizes.
//
// IT LIVES HERE BECAUSE EVERY CONSUMER NEEDS THE SAME LIST AND NONE OF THEM
// CAN DERIVE IT. The proxy and the browser client appraise NODES with it; a
// node appraises its own ACI/1 UPSTREAM with it. Those are different questions
// about the same fleet of guest images, and two Go copies reaching different
// verdicts on identical evidence is the failure the shared attest module
// exists to prevent. `zs-proxy`'s defaultTrustedOSImages delegates here, and
// proto/ts/src/attest/trust-lists.ts, which the TS SDK and the browser client
// read, is generated from it (TestTrustListTwinVectors fails while that file
// is stale).
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
// `phala os-images`, regenerate the TypeScript twin
// (`go test ./attest -run TestTrustListTwinVectors -update-trust-lists`) and
// the compose vectors, and update the two hand copies in the same change: the
// live test's assets table (which fails while it is missing an entry) and
// node/internal/tee/dstackprobe.sh's ds_os_image_hash, which nothing pins.
// Images before 0.6.0 are `Dstack-TEE/meta-dstack` releases; from 0.6.0 they
// are `mkosi-os-v*` releases of `Dstack-TEE/dstack`, built by a different
// backend, with the digest also listed in that release's image-hashes.txt.
//
// Removing an entry de-routes every node still on that image, and refuses any
// ACI upstream on it too, since node's upstream attestation reads this list.
//
// Returns a fresh slice per call: it lands in config structs callers mutate,
// and a shared backing array would let one embedder's append be observed by
// the next.
func TrustedDstackOSImages() []string {
	return []string{
		// What pins these in the DEFAULT suite is weaker than it looks:
		// testdata/compose_vectors.json and the TypeScript twin are both
		// generated from this list, so a changed digit goes red in
		// TestComposeVectors and TestTrustListTwinVectors only as a
		// DISAGREEMENT with a stale copy. Regenerating satisfies them, and
		// a digit wrong here is wrong in every copy and invisible to both.
		// TestLive_TrustedOSImages_MatchTheVendorRelease
		// (`-tags osimageslive`) is the only check that the value is right.
		// Run it when adding or changing an entry.
		//
		// Every entry below was confirmed against the vendor release:
		// digest.txt is this exact string AND equals sha256(sha256sum.txt).
		// The second equality is what makes the value mean something,
		// because sha256sum.txt commits to ovmf.fd, bzImage,
		// initramfs.cpio.gz and metadata.json, and metadata.json carries the
		// dm-verity rootfs hash. So the one number dstack measures
		// transitively fixes firmware, kernel, initramfs and rootfs.

		// dstack-0.5.9 (meta-dstack v0.5.9, confirmed 2026-09-25). No
		// longer offered by `phala os-images`, and kept for two reasons:
		// Phala's ACI gateway (inference.phala.com) still replays this
		// digest as of 2026-10-19, and it is in OSImagesWithoutSSHDaemon,
		// which must stay a subset of this list. Drop it once the gateway and our own
		// fleet have moved off it. The same digest is pinned by
		// proto/testdata/attest_vectors.json and the dstack verifier's
		// tests, which were captured on it.
		"bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033",

		// dstack-0.5.12 (meta-dstack v0.5.12, confirmed 2026-10-19).
		"8db40cb23008d6213668b5816702d100b37b859a8a5bfd18d938ae3a1b3715bd",

		// dstack-nvidia-0.5.12, the GPU line (meta-dstack v0.5.12,
		// confirmed 2026-10-19). It replaced dstack-nvidia-0.5.9, which was
		// removed here: a GPU node still on that image is refused.
		"91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829",

		// dstack-0.6.1 (Dstack-TEE/dstack mkosi-os-v0.6.1, confirmed
		// 2026-10-19; also the os_image_hash in that release's
		// image-hashes.txt). CPU only: the release ships no nvidia image.
		"ec43cb8c5e04b6bb6c53b33b16076a01d83d01f7f4b703f2f78a0d947d6247e6",
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
// THE PROCEDURE, run identically on both entries on 2026-10-19:
//
//  1. Bind the rootfs to the digest. digest.txt == sha256(sha256sum.txt), every
//     listed artifact re-hashes to its entry, and `veritysetup verify` of
//     rootfs.img.verity against the dstack.rootfs_hash= and dstack.rootfs_size=
//     values in metadata.json's cmdline passes — the same parameters the
//     initramfs /init hands to
//     `veritysetup open` at boot. A one-digit-wrong root hash was confirmed to
//     fail, so the pass means something. Without this step the scan describes a
//     file with the right name, not the bytes that boot.
//  2. List the squashfs DIRECTORY TABLE (`unsquashfs -lls`) and the initramfs
//     (`cpio -it`), and ASSERT THE CONTROL NAMES PRESENT (systemd, busybox,
//     bash, docker, containerd, dstack-guest-agent, init, mount, modprobe, sh;
//     all ten in the rootfs). A raw byte scan is not the procedure: squashfs
//     keeps names in zlib-compressed metadata blocks, so grepping the image
//     reports a confident false clean, which is what the first attempt did.
//  3. No SSH server and nothing that reads authorized_keys: absent from both
//     are sshd, ssh, openssh, dropbear, tinyssh, ssh-keygen, ssh-agent,
//     sshd_config, authorized_keys and host keys. The only "ssh" names are
//     libssh.so.4 (and its target libssh.so.4.9.6), cryptsetup-ssh and
//     libcryptsetup-token-ssh.so, which are systemd-cryptenroll's SSH-token
//     plugin, a client library.
//  4. No console login is STARTED, which is narrower than "none is present".
//     The initramfs carries busybox getty, shadow login, su and sulogin, and
//     the rootfs carries su, sulogin and systemd-sulogin-shell.
//     - getty/login: the initramfs /init only opens verity and switch_roots
//     (under set -e, so a failure panics rather than dropping to a shell).
//     The rootfs has no agetty, no getty@ / serial-getty@ unit and no
//     systemd-getty-generator; multi-user.target's wants/getty.target is a
//     dangling symlink. So console=ttyS0 produces no serial getty.
//     - sulogin: its only starters are emergency.service and rescue.service.
//     Every OnFailure=emergency.target is on a boot-time unit (initrd-*,
//     local-fs.target, systemd-fsck-root), all of which settle before
//     dstack-prepare.service — ordered after network-online — mounts the
//     writable overlay on /etc. Until then root is locked (`*` in both
//     images' /etc/shadow). That ordering is what makes DSTACK_ROOT_PASSWORD
//     inert too, not the lock alone: the pre-launch script can set a
//     password for the rest of that boot, but nothing reaches sulogin
//     afterwards. The overlay's upper dir is tmpfs (/var/volatile), so a
//     reboot restores the lock. kernel.sysrq = 16 (sync only), and
//     ctrl-alt-del.target is reboot.target.
//     The 2026-09-25 write-up of 0.5.9
//     (plans/future/tee/phala-revalidation-2026-09-25.md § 9.2) said getty and
//     login were absent; they were not, and that sentence is wrong.
//
// TWO PREMISES THE SCAN CANNOT CHECK. First, the kernel command line is the
// published one (metadata.json's cmdline). The rootfs ships
// systemd-run-generator and systemd-debug-generator, so `systemd.run=` or
// `systemd.unit=emergency.target` plus `SYSTEMD_SULOGIN_FORCE` on a host-chosen
// cmdline would give root with every name above unchanged. The cmdline is
// measured into RTMR2, and this package's verifier checks os-image-hash from
// the RTMR3 replay but does not appraise RTMR0-2. Second, the scan covers the
// IMAGE, not the upstream's own containers; see ComposePolicy
// .RootBackdoorSafeOSImages for that half.
//
// dstack-0.5.9: rootfs 2310 inodes, initramfs 637 entries.
// dstack-0.5.12: rootfs 2850 inodes, initramfs 637 entries; the login-relevant
// set is identical to 0.5.9's.
//
// dstack-nvidia-0.5.12 AND dstack-0.6.1 ARE NOT HERE, and their absence is a
// fact rather than an oversight: they are trusted, but their rootfs has not
// been enumerated. The nvidia rootfs is a different, larger image, and 0.6.1 is
// a different build (Debian/mkosi), so neither inherits a scan. An upstream on
// either gets the STRICT root-backdoor rule. Add an image once its scan is run,
// not before.
func OSImagesWithoutSSHDaemon() []string {
	return []string{
		"bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033", // dstack-0.5.9
		"8db40cb23008d6213668b5816702d100b37b859a8a5bfd18d938ae3a1b3715bd", // dstack-0.5.12
	}
}
