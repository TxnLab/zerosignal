/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// BootChain is what a dstack guest image's boot measures, for one image.
//
// WHY RTMR3 IS NOT ENOUGH. Guest software extends RTMR3, so compose-hash and
// os-image-hash are true only if the kernel doing the extending is dstack's.
// A TDX guest running a kernel its operator controls can write dstack-shaped
// events carrying any compose and any trusted os-image-hash, and every RTMR3
// check passes. MRTD (the firmware), RTMR1 (the kernel) and RTMR2 (the kernel
// command line and initramfs) are extended before any guest code runs, so they
// say whose kernel that was. RTMR2 covers the command line, and with it
// dstack.rootfs_hash=, which the initramfs opens the rootfs against with
// dm-verity, so pinning RTMR2 pins the rootfs too.
//
// RTMR0 IS A SET. It measures the TD HOB and the ACPI tables, which the host's
// VMM writes from the instance shape: measured 2026-10-23, it differs between
// Phala's tdx.small and tdx.large and is identical across images for the same
// shape. So each image carries the RTMR0 values measured for it, one per
// shape. A shape nobody measured is refused, and a new shape is a measurement
// to take, the same way a new image is.
type BootChain struct {
	// OSImage is the os-image-hash the RTMR3 replay reports for this image,
	// the key every verifier looks the row up by.
	OSImage string
	// Name is the image's release name, for messages only.
	Name string
	// MRTD, RTMR1 and RTMR2 are fixed per image. Empty on a row whose image is
	// trusted but not yet measured, which VerifyBootChain refuses.
	MRTD, RTMR1, RTMR2 string
	// RTMR0 holds one value per measured instance shape.
	RTMR0 []string
}

func (b BootChain) measured() bool {
	return b.MRTD != "" && b.RTMR1 != "" && b.RTMR2 != "" && len(b.RTMR0) > 0
}

// TrustedDstackBootChains are the boot measurements of every image in
// TrustedDstackOSImages, in the same order: that list is derived from this one,
// so an image cannot be trusted without a row here.
//
// THE VALUES COME FROM BOOTING THE IMAGE, not from a calculation. Each was read
// from Intel-signed quotes of CVMs we deployed with node/internal/tee/
// dstackprobe.sh `matrix`, whose boot logs replay to these registers (the
// rows measured 2026-11-20 took the quote and log from Phala's attestation
// API, with each quote checked against Intel's chain and each log's
// os-image-hash and app-id replayed against it), and the
// MRTD/RTMR1/RTMR2 of an image agreed across every shape and host it ran on.
// Adding an image or a shape means running that grid for it first: an image
// whose row is not measured is refused, and so is a shape whose RTMR0 is not
// listed. Phala changing its VMM can move RTMR0 for the whole fleet at once,
// which reads exactly like a fleet of forged quotes; a refusal on RTMR0 alone,
// with MRTD/RTMR1/RTMR2 matching, is the first thing to check.
//
// Returns fresh slices per call, as TrustedDstackOSImages does.
func TrustedDstackBootChains() []BootChain {
	const (
		// One value per Phala instance shape, identical on every image
		// measured so far.
		rtmr0Small = "68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96" // tdx.small, 1 vCPU / 2 GiB
		rtmr0Large = "fb14dc139f33d6fcf474bc8332cac001259fb31cfbcb6b34d4ceeb552a2c4466884a0cbde45ad98a05c5c060c23ad65a" // tdx.large, 4 vCPU / 8 GiB
	)
	return []BootChain{
		{
			// dstack-0.5.9 (meta-dstack v0.5.9, confirmed 2026-09-25). No
			// longer offered by `phala os-images`, and kept for two reasons:
			// Phala's ACI gateway (inference.phala.com) still replays this
			// digest as of 2026-10-19, and it is in OSImagesWithoutSSHDaemon,
			// which must stay a subset of this list. Drop it once the gateway
			// and our own fleet have moved off it. The same digest is pinned by
			// proto/testdata/attest_vectors.json and the dstack verifier's
			// tests, which were captured on it.
			//
			// Measured on our 2026-08 tdx.small capture and on the ACI gateway's
			// quotes of 2026-10-21, which agree on MRTD/RTMR1/RTMR2. The
			// gateway's RTMR0 is its own shape, which we could not deploy:
			// the image is gone from Phala's catalogue.
			OSImage: "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033",
			Name:    "dstack-0.5.9",
			MRTD:    "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
			RTMR1:   "07e6f51aa763abfe75c3ddfbf4f425fe3f0ceff66d807a75e049303dce9addf68e7218729bd419638af63a370f65878c",
			RTMR2:   "df67e467e60edc1737bcf8e682d48131bfb427f523226aa7f197a7608e9b3784783fa759ef5b28191fa12f9ddb36b858",
			RTMR0: []string{
				rtmr0Small,
				"46a83f6bbbeaa274aaf04861ef47d7e8898d4e699126b642f72f582e8d7f5349cb266a188bbabf619940d4fece06594b", // Phala's ACI gateway
			},
		},
		{
			// dstack-0.5.12 (meta-dstack v0.5.12, confirmed 2026-10-19).
			// Measured 2026-10-23: tdx.small twice and tdx.large.
			OSImage: "8db40cb23008d6213668b5816702d100b37b859a8a5bfd18d938ae3a1b3715bd",
			Name:    "dstack-0.5.12",
			MRTD:    "7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173",
			RTMR1:   "4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec",
			RTMR2:   "764489f277a8540189761e72b4238ba36d4d647e11bd958d8ab5522af2a4867b0ff63e06b0c4967f1857236244040a5d",
			RTMR0:   []string{rtmr0Small, rtmr0Large},
		},
		{
			// dstack-nvidia-0.5.12, the GPU line (meta-dstack v0.5.12,
			// confirmed 2026-10-19). It replaced dstack-nvidia-0.5.9, which was
			// removed here: a GPU node still on that image is refused.
			//
			// NOT YET MEASURED, so every GPU node is refused until the GPU
			// grid row is run and its values are filled in here.
			OSImage: "91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829",
			Name:    "dstack-nvidia-0.5.12",
		},
		{
			// dstack-0.6.1 (Dstack-TEE/dstack mkosi-os-v0.6.1, confirmed
			// 2026-10-19; also the os_image_hash in that release's
			// image-hashes.txt). CPU only: the release ships no nvidia image.
			// Measured 2026-10-23: tdx.small on two hosts and tdx.large.
			OSImage: "ec43cb8c5e04b6bb6c53b33b16076a01d83d01f7f4b703f2f78a0d947d6247e6",
			Name:    "dstack-0.6.1",
			MRTD:    "2a674327c50218dba880066b349b8d559d749ed68dce33fd651c184a877d084b07a9e583767a7ad5da13ed91deec2b70",
			RTMR1:   "89ef86c5125b986c325f0a94acfa87718a4ef3a4d4f237dbb72dda3cf777fd2c054555fb4407eb53338d7d67329a7333",
			RTMR2:   "e9000e338f33233e8f51b7fd031e1c158bdcf8572eab041c0bc8eb7fef48b23259a6a556e6c8e2af99999fc39c793179",
			RTMR0:   []string{rtmr0Small, rtmr0Large},
		},
		{
			// dstack-0.6.4 (Dstack-TEE/dstack mkosi-os-v0.6.4, confirmed
			// 2026-11-20). CPU only. Measured 2026-11-20: tdx.small and
			// tdx.large on Phala's prod5 host, read from `phala cvms
			// attestation` as 0.6.5's were. MRTD and RTMR0 are 0.6.1's.
			OSImage: "feff3645893ad910d4f0e06d8f553cf80a7c9fede2ce0698fa63116283260366",
			Name:    "dstack-0.6.4",
			MRTD:    "2a674327c50218dba880066b349b8d559d749ed68dce33fd651c184a877d084b07a9e583767a7ad5da13ed91deec2b70",
			RTMR1:   "0d390cdff163d981adbe90bb1d3666463be9de93a83de9b09ad0fe233974fdddc475731ba40d0bdc523efe8887cf82b8",
			RTMR2:   "df939336955fec7a8d316b4ee4fe7b7e0810194c6911aa61c559882ad17984bfb4a7fc7c3112d25a4968f23bd6b907be",
			RTMR0:   []string{rtmr0Small, rtmr0Large},
		},
		{
			// dstack-0.6.5 (Dstack-TEE/dstack mkosi-os-v0.6.5, confirmed
			// 2026-11-20; the release ships no image-hashes.txt). CPU only.
			// Measured 2026-11-20: tdx.small twice and tdx.large, all on
			// Phala's prod5 host, read from `phala cvms attestation` because
			// the container log was not served. MRTD and RTMR0 are 0.6.1's;
			// RTMR1 and RTMR2 are its own, and match a production node's quote.
			OSImage: "4771a29e03e93f0e2d5e37174cd8bb1112942c9689deb36b16c5df9e183d8623",
			Name:    "dstack-0.6.5",
			MRTD:    "2a674327c50218dba880066b349b8d559d749ed68dce33fd651c184a877d084b07a9e583767a7ad5da13ed91deec2b70",
			RTMR1:   "2f72a4db2f7de90adeabe55607b0c1cf209fc243bc773f5862d1b00d3bb198e835e99d502e90a24005f0d1368dd24f29",
			RTMR2:   "3d9910a33a26a769c5146dea31bea0d2924a7746ad09e121dabe709eddd5c647716f4d89279e0e24d8dbb93f9cdb605b",
			RTMR0:   []string{rtmr0Small, rtmr0Large},
		},
	}
}

var (
	// ErrBootChainUnknown means no row names the replayed os-image-hash, or
	// the row's image has not been measured yet.
	ErrBootChainUnknown = errors.New("attest: no measured boot chain for this OS image")
	// ErrBootChainMismatch means a boot register differs from the image's row.
	ErrBootChainMismatch = errors.New("attest: the quote's boot chain is not the image's")
)

// VerifyBootChain checks the quote's MRTD and RTMR0-2 against the row for
// osImage, the os-image-hash the RTMR3 replay recovered.
//
// The row is chosen by the REPLAYED os-image-hash and then the hardware
// registers must agree with it. That is the cross-check that matters: a guest
// on another image, or on a kernel of its operator's, claiming a trusted
// os-image-hash in RTMR3 is refused here because its boot registers are the
// other image's.
//
// Values compare by ASCII lowercase rather than strings.EqualFold, whose
// Unicode folding the TypeScript twin's toLowerCase does not reproduce.
func VerifyBootChain(quote []byte, osImage string, chains []BootChain) error {
	var row *BootChain
	for i := range chains {
		if osImage != "" && sameHex(chains[i].OSImage, osImage) {
			row = &chains[i]
			break
		}
	}
	if row == nil {
		return fmt.Errorf("%w (os-image-hash %q)", ErrBootChainUnknown, osImage)
	}
	if !row.measured() {
		return fmt.Errorf("%w (%s is trusted but not yet measured)", ErrBootChainUnknown, row.Name)
	}
	reg := func(name string, got []byte, ok bool) (string, error) {
		if !ok {
			return "", fmt.Errorf("%w to hold %s: got %d bytes", ErrShortQuote, name, len(quote))
		}
		return hex.EncodeToString(got), nil
	}
	mrtd, ok := QuoteMRTD(quote)
	got, err := reg("MRTD", mrtd, ok)
	if err != nil {
		return err
	}
	if !sameHex(got, row.MRTD) {
		return fmt.Errorf("%w: MRTD %s is not %s's", ErrBootChainMismatch, got, row.Name)
	}
	for _, n := range []int{1, 2} {
		r, ok := QuoteRTMR(quote, n)
		if got, err = reg(fmt.Sprintf("RTMR%d", n), r, ok); err != nil {
			return err
		}
		want := row.RTMR1
		if n == 2 {
			want = row.RTMR2
		}
		if !sameHex(got, want) {
			return fmt.Errorf("%w: RTMR%d %s is not %s's", ErrBootChainMismatch, n, got, row.Name)
		}
	}
	r0, ok := QuoteRTMR(quote, 0)
	if got, err = reg("RTMR0", r0, ok); err != nil {
		return err
	}
	for _, v := range row.RTMR0 {
		if sameHex(got, v) {
			return nil
		}
	}
	return fmt.Errorf("%w: RTMR0 %s matches no measured instance shape of %s "+
		"(MRTD, RTMR1 and RTMR2 match, so this is a host configuration nobody measured)",
		ErrBootChainMismatch, got, row.Name)
}

func sameHex(a, b string) bool { return asciiLower(a) == asciiLower(b) }

// Bytewise, so invalid UTF-8 is compared as it is rather than folded to
// U+FFFD the way strings.Map would.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
