/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/details_deployment_vectors.json: whether a
// node's advertised deployment lets the payer route to it
// (checkDetailsDeployment). The TS SDK mirrors it in sdk/src/catalog/deployment.ts.
//
//	cd proto/go && go test ./zs -run TestDetailsDeploymentVectors -update

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/ticket"
)

const detailsDeploymentVectorsPath = "../../testdata/details_deployment_vectors.json"

// Deployment is the payer's own (absent: unknown), Advertised the node's
// details field and ProtoVersion its advertised version.
type detailsDeploymentCase struct {
	Name         string `json:"name"`
	Deployment   string `json:"deployment,omitempty"`
	Advertised   string `json:"advertised,omitempty"`
	ProtoVersion string `json:"proto_version,omitempty"`
	Admitted     bool   `json:"admitted"`
}

func detailsDeploymentCases() []detailsDeploymentCase {
	depOf := func(fill byte) string {
		d, err := ticket.AlgorandDeploymentID(bytes.Repeat([]byte{fill}, 32), 1001)
		if err != nil {
			panic(err)
		}
		return d.String()
	}
	mine, other := depOf(1), depOf(2)
	raw, err := base64.StdEncoding.DecodeString(mine)
	if err != nil {
		panic(err)
	}
	urlSafe := base64.URLEncoding.EncodeToString(raw)
	if urlSafe == mine {
		panic("the URL-safe case needs an id whose base64 holds + or /")
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := len(mine) - 2 // the character before the one "="
	padBits := mine[:i] + string(alphabet[strings.IndexByte(alphabet, mine[i])|0x03]) + mine[i+1:]
	if padBits == mine {
		panic("the padding-bits case must change the encoding")
	}
	return []detailsDeploymentCase{
		{Name: "a 9.14 node on this deployment", Deployment: mine, Advertised: mine, ProtoVersion: "9.14"},
		{Name: "a 9.14 node naming none", Deployment: mine, ProtoVersion: "9.14"},
		{Name: "a 9.13 node on this deployment", Deployment: mine, Advertised: mine, ProtoVersion: "9.13"},
		{Name: "a 9.13 node on another deployment", Deployment: mine, Advertised: other, ProtoVersion: "9.13"},
		{Name: "an older node naming another deployment", Deployment: mine, Advertised: other, ProtoVersion: "9.12"},
		{Name: "a 9.13 node naming none", Deployment: mine, ProtoVersion: "9.13"},
		{Name: "a later major naming none", Deployment: mine, ProtoVersion: "10.0"},
		{Name: "a 9.12 node naming none", Deployment: mine, ProtoVersion: "9.12"},
		{Name: "a node with no version naming none", Deployment: mine},
		{Name: "a payer with no deployment, a node naming one", Advertised: other, ProtoVersion: "9.13"},
		{Name: "a payer with no deployment, a 9.13 node naming none", ProtoVersion: "9.13"},
		{Name: "a deployment that is not 32 bytes", Deployment: mine, Advertised: "AAAA", ProtoVersion: "9.13"},
		{Name: "a deployment that is not base64", Deployment: mine, Advertised: "!" + mine[1:], ProtoVersion: "9.13"},
		{Name: "an all-zero deployment", Deployment: mine, Advertised: base64.StdEncoding.EncodeToString(make([]byte, 32)), ProtoVersion: "9.13"},
		{Name: "a malformed deployment to a payer that knows none", Advertised: "AAAA", ProtoVersion: "9.13"},
		// Go's base64 decoder skips CR and LF anywhere in its input.
		{Name: "this deployment with a line break", Deployment: mine, Advertised: mine[:20] + "\r\n" + mine[20:], ProtoVersion: "9.13"},
		{Name: "this deployment with a space", Deployment: mine, Advertised: mine[:20] + " " + mine[20:], ProtoVersion: "9.13"},
		// StdEncoding (not Strict) ignores the unused low bits of the character
		// before the padding; 32 bytes leave two of them.
		{Name: "this deployment with set padding bits", Deployment: mine, Advertised: padBits, ProtoVersion: "9.13"},
		{Name: "this deployment unpadded", Deployment: mine, Advertised: strings.TrimRight(mine, "="), ProtoVersion: "9.13"},
		{Name: "this deployment in the URL-safe alphabet", Deployment: mine, Advertised: urlSafe, ProtoVersion: "9.13"},
		{Name: "an all-zero deployment to a payer that knows none", Advertised: base64.StdEncoding.EncodeToString(make([]byte, 32)), ProtoVersion: "9.13"},
		{Name: "an older node naming this deployment", Deployment: mine, Advertised: mine, ProtoVersion: "9.12"},
	}
}

func TestDetailsDeploymentVectors(t *testing.T) {
	cases := detailsDeploymentCases()
	for i, c := range cases {
		var payer ticket.DeploymentID
		if c.Deployment != "" {
			if err := payer.UnmarshalText([]byte(c.Deployment)); err != nil {
				t.Fatalf("%s: deployment: %v", c.Name, err)
			}
		}
		resp := inject.OperatorDetails{Deployment: c.Advertised, ProtoVersion: c.ProtoVersion}
		cases[i].Admitted = checkDetailsDeployment(resp, payer) == nil
	}
	f := struct {
		Comment string                  `json:"comment"`
		Cases   []detailsDeploymentCase `json:"cases"`
	}{
		Comment: "Generated by proto/go/zs TestDetailsDeploymentVectors. Each case is a node's /v1/zs/details deployment field (advertised, base64; absent: none) and proto_version, checked by a payer whose own deployment id is deployment (absent: unknown). admitted is whether the probe counts as a success; a refused node is a failed probe. proto_version decides nothing: it is unsigned, so a node naming no deployment is refused at every version, as is every node to a payer that knows none.",
		Cases:   cases,
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(detailsDeploymentVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(detailsDeploymentVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("details deployment verdicts differ from %s; if the change is intended, regenerate with -update and review the diff", detailsDeploymentVectorsPath)
	}
}
