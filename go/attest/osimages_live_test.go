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
	"encoding/json"
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
//	go test -tags osimageslive -timeout 60m -run TestLive_TrustedOSImages ./attest/
//
// Build-tagged because it fetches from GitHub, and slow because some archives
// put the rootfs ahead of the small files (up to ~500MB read per asset; about
// two minutes for the whole list on 2026-10-19). Deliberately
// NOT in the default suite: these values move on Phala's schedule with no
// automation, so a vendor outage or a retired release asset must not turn into
// a red build on work that has nothing to do with them.
//
// WHY IT EXISTS AS MORE THAN A FORMALITY. The digests are hand-kept in
// osimages.go, node's dstackprobe.sh and this test's assets table;
// testdata/compose_vectors.json and
// ts/src/attest/trust-lists.ts are generated from osimages.go. What pins them
// today compares the copies TO EACH OTHER — so a changed digit goes red as
// "these disagree", which regenerating satisfies, and a digit wrong in
// osimages.go is wrong in every generated copy and completely invisible. That
// last case is not hypothetical bookkeeping: a wrong digest here
// refuses every node on that guest image, silently, with nothing logged
// operator-side, and it reads as a dev-image rejection rather than a typo.
//
// WHAT IT PROVES. Each digest equals the release's digest.txt AND equals
// sha256(sha256sum.txt) — the identity that makes the value meaningful, since
// sha256sum.txt commits to ovmf.fd, bzImage, initramfs.cpio.gz and
// metadata.json, the last carrying the dm-verity rootfs hash. So the measured
// number transitively fixes firmware, kernel, initramfs and every byte of the
// rootfs. And the asset's own metadata.json says `is_dev: false`, which is
// what rules out a DEV image: a dev guest image verifies identically on every
// other check here and in the whole attestation path while its hardening
// guarantees do not hold. metadata.json is read from the same archive and its
// hash is pinned by sha256sum.txt, which the digest is the hash of, so a
// digest cannot pass both checks while naming a dev image — provided the
// vendor sets is_dev truthfully in its dev builds, which this test trusts.
//
// THE ONE STEP IT CANNOT PROVE: that the downloaded artifact is the one that
// BOOTED. That is sha384(initramfs.cpio.gz) against the RTMR2 "Linux initrd"
// event digest in a live attestation, so it needs a capture from the image in
// question and can never be a unit test. See
// plans/future/tee/phala-revalidation-2026-09-25.md § 9.4.
//
// A failure here is not automatically our defect: read the error before
// concluding anything. A retired asset, a renamed release, or a vendor
// re-publish all look the same as a wrong constant from inside this test.
func TestLive_TrustedOSImages_MatchTheVendorRelease(t *testing.T) {
	// The release asset each trusted digest comes from. A map keyed BY DIGEST so
	// the coverage assertion below can be exact.
	assets := map[string]releaseAsset{
		"bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033": metaDstack("v0.5.9", "dstack-0.5.9"),
		"8db40cb23008d6213668b5816702d100b37b859a8a5bfd18d938ae3a1b3715bd": metaDstack("v0.5.12", "dstack-0.5.12"),
		"91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829": metaDstack("v0.5.12", "dstack-nvidia-0.5.12"),
		"ec43cb8c5e04b6bb6c53b33b16076a01d83d01f7f4b703f2f78a0d947d6247e6": mkosiOS("v0.6.1", "dstack-0.6.1"),
		"feff3645893ad910d4f0e06d8f553cf80a7c9fede2ce0698fa63116283260366": mkosiOS("v0.6.4", "dstack-0.6.4"),
		"4771a29e03e93f0e2d5e37174cd8bb1112942c9689deb36b16c5df9e183d8623": mkosiOS("v0.6.5", "dstack-0.6.5"),
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

	for digest, asset := range assets {
		t.Run(asset.name, func(t *testing.T) {
			files := mustFetchReleaseTextFiles(t, asset)

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

			// The metadata.json read here must be the one the digest commits
			// to, or its is_dev says nothing about this image.
			meta := sha256.Sum256([]byte(files["metadata.json"]))
			if h := hex.EncodeToString(meta[:]); h != covered["metadata.json"] {
				t.Fatalf("sha256(metadata.json) = %s, but sha256sum.txt lists %s — the "+
					"is_dev read below would describe some other file", h, covered["metadata.json"])
			}
			// NO TRUSTED DIGEST MAY BE A DEV IMAGE'S. A *bool so an absent key
			// is a failure rather than reading as false.
			var md struct {
				IsDev *bool `json:"is_dev"`
			}
			if err := json.Unmarshal([]byte(files["metadata.json"]), &md); err != nil {
				t.Fatalf("metadata.json does not parse: %v\n%s", err, files["metadata.json"])
			}
			if md.IsDev == nil {
				t.Fatalf("metadata.json carries no is_dev, so nothing here rules out a dev "+
					"image:\n%s", files["metadata.json"])
			}
			if *md.IsDev {
				t.Errorf("TRUSTED DIGEST %s IS A DEV IMAGE (%s).\nA dev guest image passes "+
					"every other check identically and its hardening guarantees do not hold; "+
					"remove it and take the production image's digest from `phala os-images` "+
					"(DEV: no).", digest, asset.name)
			}
		})
	}
}

// releaseAsset is one guest-image tarball and where the vendor publishes it.
type releaseAsset struct {
	name string // the tarball's base name, e.g. dstack-0.5.12
	url  string
}

// metaDstack names an asset of a Dstack-TEE/meta-dstack release, where guest
// images before 0.6.0 are published.
func metaDstack(tag, name string) releaseAsset {
	return releaseAsset{name: name, url: fmt.Sprintf(
		"https://github.com/Dstack-TEE/meta-dstack/releases/download/%s/%s.tar.gz", tag, name)}
}

// mkosiOS names an asset of a `mkosi-os-*` release of Dstack-TEE/dstack, where
// guest images are published from 0.6.0 on.
func mkosiOS(version, name string) releaseAsset {
	return releaseAsset{name: name, url: fmt.Sprintf(
		"https://github.com/Dstack-TEE/dstack/releases/download/mkosi-os-%s/%s.tar.gz", version, name)}
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

// mustFetchReleaseTextFiles is fetchReleaseTextFiles where a fetch failure means
// the test cannot run at all.
func mustFetchReleaseTextFiles(t *testing.T, asset releaseAsset) map[string]string {
	t.Helper()
	files, err := fetchReleaseTextFiles(asset)
	if err != nil {
		t.Fatalf("%v\n\nA retired asset, a renamed release and a wrong constant all look "+
			"identical from in here — check the release before changing any digest.", err)
	}
	return files
}

// fetchReleaseTextFiles returns the small text files from the tarball, reading
// only as far as the last of them.
//
// No byte range is requested. Where the files sit moves between releases —
// within the first 31MB on 0.5.9 and 0.6.1, after a 166MB rootfs on 0.5.12 and
// a ~500MB one on the nvidia line — so any fixed cap goes stale on the next
// image, and the failure it causes says nothing about the digest. The stream
// is abandoned once all three files are in hand.
func fetchReleaseTextFiles(asset releaseAsset) (map[string]string, error) {
	// Per asset; four of them must fit the documented -timeout 60m.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w (network failure, not a wrong constant)", asset.url, err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only fetch
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", asset.url, resp.Status)
	}

	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("gzip %s: %w", asset.name, err)
	}

	want := map[string]bool{"digest.txt": true, "sha256sum.txt": true, "metadata.json": true}
	out := make(map[string]string, len(want))
	tr := tar.NewReader(zr)
	for len(out) < len(want) {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", asset.name, err)
		}
		name := h.Name
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		if !want[name] {
			continue
		}
		// Bounded: these are a 65-byte digest, a short checksum list and a
		// sub-kilobyte JSON document. An unbounded ReadAll here would buy an
		// arbitrary allocation from a hostile or simply different archive.
		b, err := io.ReadAll(io.LimitReader(tr, 1<<16))
		if err != nil {
			return nil, fmt.Errorf("read %s from %s: %w", name, asset.name, err)
		}
		out[name] = string(b)
	}

	for name := range want {
		if _, ok := out[name]; !ok {
			return nil, fmt.Errorf("%s carries no %s — the archive layout changed; this is "+
				"NOT evidence about the digest", asset.name, name)
		}
	}
	return out, nil
}
