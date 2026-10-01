/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package imageprice_test

// Cross-impl byte-parity test for the image-pricing primitive. Generates /
// verifies proto/testdata/image_vectors.json — a language-neutral fixture
// pinning the normalized size, parsed dimensions, the reduced Factor rational,
// and the per-image / per-n microUSDC charge for a battery of (size, quality)
// inputs at fixed sample rates. proto/ts loads the same file and asserts its
// TypeScript port produces identical numbers, so any drift between the Go and
// TS imageprice logic fails on both sides — which is exactly what would
// otherwise desync the node reserve gate from the proxy/client reserve sizing
// (→ image_budget_exceeded).
//
// To regenerate after an intentional change:
//
//	cd proto/go && go test ./imageprice -run TestVectors -update
//
// Without -update, this asserts the on-disk file matches current Go output.

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/TxnLab/zerosignal/go/imageprice"
)

var updateVectors = flag.Bool("update", false, "regenerate proto/testdata/image_vectors.json")

const vectorsPath = "../../testdata/image_vectors.json"

type factorCase struct {
	Size              string   `json:"size"`
	Quality           string   `json:"quality"`
	NormalizedSize    string   `json:"normalized_size"`
	NormalizedOK      bool     `json:"normalized_ok"`
	W                 int      `json:"w"`
	H                 int      `json:"h"`
	DimsOK            bool     `json:"dims_ok"`
	FactorNum         uint64   `json:"factor_num"`
	FactorDen         uint64   `json:"factor_den"`
	PerImageMicroUSDC []uint64 `json:"per_image_micro_usdc"` // aligned with sample_rates
}

type costCase struct {
	ImageRate         uint64 `json:"image_rate"`
	N                 int    `json:"n"`
	Size              string `json:"size"`
	Quality           string `json:"quality"`
	ExpectedMicroUSDC uint64 `json:"expected_micro_usdc"`
}

type imageVectorsFile struct {
	Version     int          `json:"version"`
	Comment     string       `json:"comment"`
	SampleRates []uint64     `json:"sample_rates"`
	Cases       []factorCase `json:"cases"`
	CostCases   []costCase   `json:"cost_cases"`
}

func buildVectors() *imageVectorsFile {
	sampleRates := []uint64{40000, 7}

	inputs := []struct{ size, quality string }{
		{"1024x1024", "standard"},
		{"1024x1024", ""},
		{"1024x1024", "medium"},
		{"1024x1024", "auto"},
		{"1024x1024", "low"},
		{"1024x1024", "high"},
		{"1024x1024", "hd"},
		{"512x512", "standard"},
		{"512x512", "high"}, // area ÷4 × quality ×4 = 1
		{"2048x2048", "standard"},
		{"2048x2048", "high"},
		{"1792x1024", "standard"}, // 7/4
		{"1024x1536", "medium"},   // 3/2
		{"768", "standard"},       // 9/16, bare-N square
		{"2k", "standard"},        // Nk shorthand → 2048²
		{"16:9", "standard"},      // aspect ratio → reference
		{"auto", "low"},           // unparseable size, low quality
		{"", "high"},              // empty size, high quality
		{"large", "standard"},     // unparseable → reference
		{"30000x30000", "high"},   // clamped to MaxDimension² (256× area)
	}

	cases := make([]factorCase, 0, len(inputs))
	for _, in := range inputs {
		ns, nok := imageprice.NormalizeSize(in.size)
		w, h, dok := imageprice.Dimensions(in.size)
		num, den := imageprice.Factor(in.size, in.quality)
		perImage := make([]uint64, len(sampleRates))
		for i, r := range sampleRates {
			perImage[i] = imageprice.PerImageMicroUSDC(r, in.size, in.quality)
		}
		cases = append(cases, factorCase{
			Size:              in.size,
			Quality:           in.quality,
			NormalizedSize:    ns,
			NormalizedOK:      nok,
			W:                 w,
			H:                 h,
			DimsOK:            dok,
			FactorNum:         num,
			FactorDen:         den,
			PerImageMicroUSDC: perImage,
		})
	}

	costInputs := []struct {
		rate    uint64
		n       int
		size    string
		quality string
	}{
		{40000, 3, "1024x1024", "standard"},
		{7, 3, "768", "standard"}, // per-image ceil then ×n: 3×4 = 12
		{40000, 1, "2048x2048", "high"},
	}
	costCases := make([]costCase, 0, len(costInputs))
	for _, ci := range costInputs {
		costCases = append(costCases, costCase{
			ImageRate:         ci.rate,
			N:                 ci.n,
			Size:              ci.size,
			Quality:           ci.quality,
			ExpectedMicroUSDC: imageprice.CostMicroUSDC(ci.rate, ci.n, ci.size, ci.quality),
		})
	}

	return &imageVectorsFile{
		Version: 1,
		Comment: "Cross-impl byte-parity vectors for hayai image pricing (imageprice). " +
			"Regenerate via: cd proto/go && go test ./imageprice -run TestVectors -update. " +
			"Loaded by proto/go/imageprice/vectors_test.go and proto/ts/test/imageprice-vectors.test.ts.",
		SampleRates: sampleRates,
		Cases:       cases,
		CostCases:   costCases,
	}
}

func TestVectors(t *testing.T) {
	v := buildVectors()
	got, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	got = append(got, '\n')

	if *updateVectors {
		if err := os.WriteFile(vectorsPath, got, 0o644); err != nil {
			t.Fatalf("write %s: %v", vectorsPath, err)
		}
		t.Logf("wrote %s (%d bytes)", vectorsPath, len(got))
		return
	}

	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v\n(run `cd proto/go && go test ./imageprice -run TestVectors -update` to generate)", vectorsPath, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s drifted from current Go output\n(run `cd proto/go && go test ./imageprice -run TestVectors -update` to regenerate)", vectorsPath)
	}
}
