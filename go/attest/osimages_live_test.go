//go:build osimageslive

/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestLive_TrustedOSImages_MatchTheVendorRelease is the ONLY check that can say
// these digests are right rather than merely consistent.
//
//	go test -tags osimageslive -run TestLive_TrustedOSImages ./attest/
//
// Build-tagged because it fetches from GitHub. Deliberately NOT in the default
// suite: these values move on Phala's schedule with no automation, so a vendor
// outage or a retired release asset must not turn into a red build on work that
// has nothing to do with them.
//
// WHY IT EXISTS AS MORE THAN A FORMALITY. The digests live in four hand-kept
// copies (here, testdata/compose_vectors.json, client's tee-allowlist.ts, and
// node's dstackprobe.sh). What pins them today is the vector, which compares our
// copies TO EACH OTHER — so one wrong digit goes red as "these two disagree",
// which either copy satisfies, and a digit wrong in ALL FOUR is completely
// invisible. That last case is not hypothetical bookkeeping: a wrong digest here
// refuses every node on that guest image, silently, with nothing logged
// operator-side, and it reads as a dev-image rejection rather than a typo.
//
// WHAT IT PROVES, AND THE ONE STEP IT CANNOT. It checks that each digest equals
// the release's digest.txt AND equals sha256(sha256sum.txt) — the identity that
// makes the value meaningful, since sha256sum.txt commits to ovmf.fd, bzImage,
// initramfs.cpio.gz and metadata.json, the last carrying the dm-verity
// rootfs_hash. So the measured number transitively fixes firmware, kernel,
// initramfs and every byte of the rootfs.
//
// TWO THINGS IT DOES NOT ESTABLISH, both needing the full ~510MB download
// because their artifacts sit past the truncation. See
// plans/future/tee/phala-revalidation-2026-09-25.md § 9.4.
//
//   - That the downloaded artifact is the one that BOOTED. That is
//     sha384(initramfs.cpio.gz) against the RTMR2 "Linux initrd" event digest in
//     a live attestation, so it needs a capture from the line in question and
//     can never be a unit test. Confirmed on the CPU line; open on the GPU line
//     for want of a GPU capture.
//   - That the image is a PRODUCTION one. `is_dev` lives in metadata.json, and
//     coverage above proves only that the digest commits to that file, not what
//     it says. A dev image verifies identically on every check here — which is
//     the whole hazard `phala os-images`' DEV column exists to warn about, and
//     the reason TrustedDstackOSImages' own godoc leads with it. Today that
//     rests on the operator having read the column correctly at the time of
//     adding.
//
// A failure here is not automatically our defect: read the error before
// concluding anything. A retired asset, a renamed release, or a vendor
// re-publish all look the same as a wrong constant from inside this test.
func TestLive_TrustedOSImages_MatchTheVendorRelease(t *testing.T) {
	// The release asset each trusted digest comes from. A map keyed BY DIGEST so
	// the coverage assertion below can be exact.
	assets := map[string]string{
		"bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033": "dstack-0.5.9",
		"806a352e16175d90568de97dff563f31f680239e6b90e9b5b2e9141d0955b0d9": "dstack-nvidia-0.5.9",
	}

	// EVERY TRUSTED DIGEST MUST BE NAMED HERE. Without this, adding an image to
	// the allowlist and forgetting this table leaves the new value unverified
	// while the test still passes — which is the same silence the whole file
	// exists to break.
	for _, d := range TrustedDstackOSImages() {
		if _, ok := assets[d]; !ok {
			t.Errorf("trusted OS image %s names no release asset in this test, so nothing "+
				"checks it against the vendor; add it to `assets`", d)
		}
	}
	if len(assets) != len(TrustedDstackOSImages()) {
		t.Errorf("this test names %d assets for %d trusted digests; a stale entry here is a "+
			"digest that was removed from the allowlist and is still being fetched",
			len(assets), len(TrustedDstackOSImages()))
	}

	for digest, release := range assets {
		t.Run(release, func(t *testing.T) {
			files := mustFetchReleaseTextFiles(t, release)

			got := strings.TrimSpace(files["digest.txt"])
			if got != digest {
				t.Errorf("digest.txt = %s\nallowlist = %s\nEvery node on this guest image is "+
					"refused while these differ, and the refusal reads as a dev image rather "+
					"than as a wrong constant.", got, digest)
			}

			// THE IDENTITY, not a second spelling of the same check: digest.txt
			// is a published constant, while this is what the constant COVERS.
			sum := sha256.Sum256([]byte(files["sha256sum.txt"]))
			if h := hex.EncodeToString(sum[:]); h != digest {
				t.Errorf("sha256(sha256sum.txt) = %s, want %s — the digest no longer commits "+
					"to the artifact list, so it fixes nothing about what runs", h, digest)
			}
			// The four artifacts the identity is worth anything because of. If
			// the vendor drops one, the transitive-coverage claim in the godoc
			// above stops being true and must be re-read before it is repeated.
			//
			// PARSED INTO ENTRIES, not substring-matched. A `Contains` check is
			// satisfied by a manifest that merely MENTIONS metadata.json — in a
			// comment, or as a path component of some other line — while
			// carrying no digest line for it. That passes while asserting
			// nothing, which is the failure this whole file exists to avoid.
			covered := parseSHA256Manifest(t, files["sha256sum.txt"])
			for _, want := range []string{"ovmf.fd", "bzImage", "initramfs.cpio.gz", "metadata.json"} {
				if _, ok := covered[want]; !ok {
					t.Errorf("sha256sum.txt has no digest entry for %s, so the measured "+
						"value no longer transitively fixes it:\n%s",
						want, files["sha256sum.txt"])
				}
			}
		})
	}

	// NO TRUSTED DIGEST MAY BE A DEV IMAGE'S.
	//
	// This is the check that stops the failure TrustedDstackOSImages' godoc leads
	// with — a dev guest image verifies identically on every other check in this
	// file and in the whole attestation path, while its hardening guarantees do
	// not hold. Until now that rested on whoever added a digest having read
	// `phala os-images`' DEV column correctly, which is a convention, not an
	// assertion.
	//
	// It works because dstack publishes the dev variants as SEPARATE assets with
	// their own digests, so metadata.json's `is_dev` — which sits past the
	// truncation and would cost the full ~510MB — is not needed to answer the
	// question.
	//
	// DERIVED, not a hardcoded list of dev digests. A static table has the same
	// defect as the asset table above without the coverage check to catch it: add
	// a guest image and its dev twin goes unlisted, so the new entry is the one
	// thing the check cannot see. Deriving the twin's NAME from the asset we
	// already trust means the set can never fall behind the allowlist.
	//
	// Compared against EVERY trusted digest rather than only its own twin,
	// because the mistake being guarded against is a paste — and a paste puts the
	// wrong value under whichever name was being edited at the time.
	t.Run("no dev image is allowlisted", func(t *testing.T) {
		trusted := TrustedDstackOSImages()
		for _, release := range assets {
			dev := devAssetName(t, release)
			files, err := fetchReleaseTextFiles(dev)
			if err != nil {
				// Deliberately an error, not a skip. A release that genuinely
				// ships no dev variant and a dev asset that was renamed look
				// identical from here, and the second silently disables the one
				// check standing between a pasted dev digest and a trusting
				// fleet. Make someone decide.
				t.Errorf("could not read the dev twin %s, so nothing here rules out a dev "+
					"digest in the allowlist: %v\nIf this release truly publishes no dev "+
					"variant, say so at devAssetName rather than leaving the check inert.",
					dev, err)
				continue
			}
			devDigest := strings.TrimSpace(files["digest.txt"])
			if len(devDigest) != 64 {
				t.Errorf("%s digest.txt is not a digest (%q)", dev, devDigest)
				continue
			}
			for _, d := range trusted {
				if d == devDigest {
					t.Errorf("TRUSTED DIGEST %s IS THE DEV IMAGE %s.\nA dev guest image "+
						"passes every other check identically and its hardening guarantees "+
						"do not hold; remove it and take the production digest from the "+
						"asset without -dev- in its name.", d, dev)
				}
			}
			t.Logf("%s = %s (not allowlisted)", dev, devDigest)
		}
	})
}

// devAssetName is the dev twin of a production release asset.
//
// dstack names them by inserting `-dev` before the version:
// dstack-0.5.9 → dstack-dev-0.5.9, dstack-nvidia-0.5.9 → dstack-nvidia-dev-0.5.9
// (both confirmed against the v0.5.9 release, 2026-09-25).
func devAssetName(t *testing.T, release string) string {
	t.Helper()
	i := strings.LastIndex(release, "-")
	if i < 0 {
		t.Fatalf("cannot derive the dev twin of %q: no version suffix to insert before", release)
	}
	return release[:i] + "-dev" + release[i:]
}

// parseSHA256Manifest reads `<64 hex>  <name>` lines into name → hash.
//
// A line whose first field is not 64 hex characters is not a digest entry and is
// skipped, which is what makes the caller's membership test mean "this artifact
// is committed to" rather than "this string occurs in the file".
func parseSHA256Manifest(t *testing.T, raw string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || len(f[0]) != 64 {
			continue
		}
		if _, err := hex.DecodeString(f[0]); err != nil {
			continue
		}
		// The name may carry a leading `*` (binary mode) or a directory.
		name := strings.TrimPrefix(f[1], "*")
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		out[name] = f[0]
	}
	if len(out) == 0 {
		t.Fatalf("sha256sum.txt parsed to no digest entries, so the coverage check below "+
			"would pass vacuously:\n%s", raw)
	}
	return out
}

// osImagesRangeBytes is how much of the tarball is fetched.
//
// digest.txt and sha256sum.txt both sit early in the archive, so the full ~510MB
// is unnecessary — but they are not adjacent (rootfs.img.verity and bzImage sit
// between them), which is what sets the size. Measured 2026-09-25: both files
// land inside the first 31MB on both releases. Raise it if a future release
// reorders the archive; the test says plainly when that happens.
const osImagesRangeBytes = 31_000_000

// mustFetchReleaseTextFiles is fetchReleaseTextFiles for the production assets,
// where a fetch failure means the test cannot run at all.
func mustFetchReleaseTextFiles(t *testing.T, release string) map[string]string {
	t.Helper()
	files, err := fetchReleaseTextFiles(release)
	if err != nil {
		t.Fatalf("%v\n\nA retired asset, a renamed release and a wrong constant all look "+
			"identical from in here — check the release before changing any digest.", err)
	}
	return files
}

// fetchReleaseTextFiles returns the small text files from a truncated fetch.
//
// It reads a RANGE and therefore hits a corrupt-stream error partway through by
// design. That error is tolerated only once both wanted files are in hand, and
// reported otherwise — a truncation that swallowed the failure would report
// "digest.txt = " and blame the constant.
//
// Returns an error rather than calling t.Fatal because one caller must survive a
// missing asset to report it as "the dev check could not run", which is a
// different finding from "this digest is wrong".
func fetchReleaseTextFiles(release string) (map[string]string, error) {
	url := fmt.Sprintf(
		"https://github.com/Dstack-TEE/meta-dstack/releases/download/v0.5.9/%s.tar.gz", release)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", osImagesRangeBytes))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w (network failure, not a wrong constant)", url, err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only fetch
	// 206 is the expected answer; 200 means the range was ignored, which still
	// works because the reads below stop early.
	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}

	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("gzip %s: %w", release, err)
	}

	want := map[string]bool{"digest.txt": true, "sha256sum.txt": true}
	out := make(map[string]string, len(want))
	tr := tar.NewReader(zr)
	for len(out) < len(want) {
		h, err := tr.Next()
		if err != nil {
			// Truncation reaches us as EOF or as an unexpected-EOF/corrupt
			// error, depending on where the cut landed. Either way it is only
			// acceptable if we already have what we came for.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
				strings.Contains(err.Error(), "unexpected EOF") {
				break
			}
			return nil, fmt.Errorf("read %s: %w", release, err)
		}
		name := h.Name
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		if !want[name] {
			continue
		}
		// Bounded: these are a 65-byte digest and a four-line checksum list. An
		// unbounded ReadAll here would buy a 31MB allocation from a hostile or
		// simply different archive.
		b, err := io.ReadAll(io.LimitReader(tr, 1<<16))
		if err != nil {
			return nil, fmt.Errorf("read %s from %s: %w", name, release, err)
		}
		out[name] = string(b)
	}

	for name := range want {
		if _, ok := out[name]; !ok {
			return nil, fmt.Errorf("%s carries no %s within the first %d bytes — if the "+
				"archive was reordered, raise osImagesRangeBytes; this is NOT evidence "+
				"about the digest", release, name, osImagesRangeBytes)
		}
	}
	return out, nil
}
