/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject_test

// Cross-impl parity vectors for InferDialect / HostMatchesDomain.
//
// DialectXAI is a security classification: it is what admits a node under
// tee.dataflow=attested_passthrough, and a TEE verifier re-applies the same
// predicate to the upstream URL bound into report_data. A verifier that
// classified a host differently from the node would either admit a lookalike
// or refuse a genuine node, so the two implementations are pinned here.
//
// Every expectation below is HAND-AUTHORED, never computed by calling
// InferDialect: a fixture derived from the function under test pins parity
// and nothing else, and the lookalike rows exist to pin correctness.
//
// Non-ASCII inputs are spelled as byte escapes so this source stays ASCII and
// no editor can silently normalize them.
//
// Regenerate after an intentional change:
//
//	cd proto/go && go test ./inject -run TestDialectVectors -update

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/TxnLab/zerosignal/go/inject"
)

const dialectVectorsPath = "../../testdata/dialect_vectors.json"

type dialectVector struct {
	URL  string         `json:"url"`
	Want inject.Dialect `json:"want"`
	Why  string         `json:"why,omitempty"`
}

type hostDomainVector struct {
	Host   string `json:"host"`
	Domain string `json:"domain"`
	Want   bool   `json:"want"`
}

type httpsHostVector struct {
	URL string `json:"url"`
	// Host is the expected host; "" means HTTPSUpstreamHost refuses the URL.
	Host string `json:"host"`
}

type admissibleVector struct {
	Name string `json:"name"`
	// PostureJSON "" means no posture.
	PostureJSON      string `json:"posture_json"`
	UpstreamAttested bool   `json:"upstream_attested"`
	Want             bool   `json:"want"`
}

type upstreamAttestedVector struct {
	// BlockJSON is the raw upstream_attestation value; "" means the key is
	// absent from the bundle.
	BlockJSON string `json:"block_json"`
	Want      bool   `json:"want"`
	Why       string `json:"why,omitempty"`
}

type dialectVectorsFile struct {
	Version          int                      `json:"version"`
	Comment          string                   `json:"comment"`
	InferDialect     []dialectVector          `json:"infer_dialect"`
	HostMatches      []hostDomainVector       `json:"host_matches_domain"`
	HTTPSHost        []httpsHostVector        `json:"https_upstream_host"`
	Admissible       []admissibleVector       `json:"named_upstream_admissible"`
	UpstreamAttested []upstreamAttestedVector `json:"upstream_attested"`
}

var dialectCases = []dialectVector{
	// Canonical vendor hosts.
	{"https://api.x.ai/v1", inject.DialectXAI, ""},
	{"https://x.ai/v1", inject.DialectXAI, "apex"},
	{"https://API.X.AI/v1", inject.DialectXAI, "hosts are case-insensitive"},
	{"https://api.x.ai./v1", inject.DialectXAI, "fully-qualified trailing dot names the same host"},
	{"https://api.x.ai:443/v1", inject.DialectXAI, "a port is not part of the host"},
	{"http://api.x.ai/v1", inject.DialectXAI, "the scheme is not a dialect question; attested_passthrough refuses http separately"},
	{"  https://api.x.ai/v1  ", inject.DialectXAI, "surrounding whitespace is trimmed, as config loading does"},
	{"https://api.openai.com/v1", inject.DialectOpenAI, ""},
	{"https://api.moonshot.ai/v1", inject.DialectMoonshot, ""},
	{"https://api.moonshot.cn/v1", inject.DialectMoonshot, ""},
	{"https://api.kimi.ai/v1", inject.DialectMoonshot, ""},
	{"https://api.kimi.com/coding/v1", inject.DialectMoonshot, ""},
	{"https://api.z.ai/api/paas/v4", inject.DialectZAI, ""},
	{"https://API.Z.AI/api/paas/v4", inject.DialectZAI, ""},
	{"https://open.bigmodel.cn/api/paas/v4", inject.DialectZAI, ""},
	{"https://openrouter.ai/api/v1", inject.DialectOpenRouter, ""},
	{"https://OPENROUTER.AI/api/v1/chat", inject.DialectOpenRouter, ""},
	{"https://api.together.xyz/v1", inject.DialectGeneric, ""},
	{"http://localhost:8000/v1", inject.DialectGeneric, ""},

	// Lookalikes. Each one classified as its vendor under the old substring
	// match; each must now be generic.
	{"https://api.x.ai.attacker.example/v1", inject.DialectGeneric, "vendor host as a PREFIX of an attacker host"},
	{"https://x.ai.attacker.example/v1", inject.DialectGeneric, "apex as a prefix — the old //x.ai pattern"},
	{"https://api.x.ai@attacker.example/v1", inject.DialectGeneric, "userinfo: reads as xAI, dials the attacker"},
	{"https://attacker.example@api.x.ai/v1", inject.DialectGeneric, "userinfo is refused even when the dialed host is genuine"},
	{"https://attacker.example/api.x.ai/v1", inject.DialectGeneric, "vendor host in the PATH"},
	{"https://attacker.example/v1?u=api.x.ai", inject.DialectGeneric, "vendor host in the QUERY"},
	{"https://attacker.example/v1#//x.ai", inject.DialectGeneric, "vendor host in the FRAGMENT"},
	{"https://notx.ai/v1", inject.DialectGeneric, "suffix without a label boundary"},
	{"https://api-x.ai.attacker.example/v1", inject.DialectGeneric, ""},
	{"https://api.openai.com.attacker.example/v1", inject.DialectGeneric, ""},
	{"https://openrouter.ai.attacker.example/api/v1", inject.DialectGeneric, "a lookalike would otherwise advertise upstream_enforced"},
	{"https://attacker.example/openrouter.ai/api/v1", inject.DialectGeneric, ""},
	{"https://openrouter.example.com/v1", inject.DialectGeneric, ""},
	{"https://my-router.example.com/v1", inject.DialectGeneric, ""},
	{"https://my-moonshot-proxy.example/v1", inject.DialectGeneric, "a vendor NAME in a host is not the vendor's domain"},
	{"https://kimi.attacker.example/v1", inject.DialectGeneric, ""},

	// Inputs that name no host.
	{"api.x.ai/v1", inject.DialectGeneric, "scheme-less: url.Parse yields a path, not a host"},
	{"", inject.DialectGeneric, ""},
	{"://api.x.ai", inject.DialectGeneric, "does not parse"},
	{"//api.x.ai/v1", inject.DialectGeneric, "scheme-relative: url.Parse finds a host, WHATWG URL refuses it"},
	{"https:api.x.ai/v1", inject.DialectGeneric, "opaque: no authority"},
	{"https:///api.x.ai/v1", inject.DialectGeneric, "empty authority"},

	// Parser-divergence shapes. Go's url.Parse and WHATWG URL resolve these
	// differently (or one refuses what the other accepts), so both sides
	// refuse them rather than risk a verifier and a node naming two hosts.
	{`https://api.x.ai\@attacker.example/v1`, inject.DialectGeneric, "WHATWG reads the backslash as a path separator"},
	{`https://attacker.example\.api.x.ai/v1`, inject.DialectGeneric, ""},
	{"https://api%2ex%2eai/v1", inject.DialectGeneric, "percent-escaped host: url.Parse errors, WHATWG decodes it to api.x.ai — refused"},
	{"https://api.x.ai/v1%zz", inject.DialectGeneric, "malformed escape in the path: url.Parse refuses it, so the TS side must too"},
	{"https://api.x.ai/v1#%zz", inject.DialectGeneric, "malformed escape in the fragment"},
	{"https://api.x.ai/v1%", inject.DialectGeneric, "a trailing bare %"},
	{"https://api.x.ai/v1?a=%zz", inject.DialectGeneric, "url.Parse keeps the query raw; refused anyway so one rule covers the string"},
	{"https://api.x.ai/v1%2F", inject.DialectXAI, "a well-formed escape in the path is fine"},
	{"https://api.x.ai/v1?a=%4z", inject.DialectGeneric, "half-valid escape: BOTH characters after % must be hex"},
	{"https://api.x.ai/v1#\x7f", inject.DialectGeneric, "DEL counts as a control byte, and url.Parse misses it in the fragment"},
	{"https://a_b.x.ai/v1", inject.DialectGeneric, "underscore: url.Parse accepts it, the LDH subset does not"},
	{"https://[::1]:8000/v1", inject.DialectGeneric, "IPv6 literal"},
	{"https://api.x.ai:abc/v1", inject.DialectGeneric, "non-numeric port"},
	{"https://api.x.ai:/v1", inject.DialectXAI, "empty port: both parsers take the host"},
	{"https://xn--x-9ga.ai/v1", inject.DialectGeneric, "punycode is plain LDH and is not x.ai"},
	{"https://api.\xd1\x85.ai/v1", inject.DialectGeneric, "Cyrillic U+0445: not LDH, refused before any IDNA mapping"},
	{"\thttps://api.x.ai/v1\n", inject.DialectXAI, "ASCII whitespace around the URL is trimmed"},
	{"\xef\xbb\xbfhttps://api.x.ai/v1", inject.DialectGeneric, "U+FEFF: non-ASCII whitespace is not trimmed on either side"},
	{"\xc2\xa0https://api.x.ai/v1", inject.DialectGeneric, "U+00A0"},
	{"https://api.x.ai/v1\x01", inject.DialectGeneric, "a control byte anywhere is refused on both sides"},
	{"https://api.x.ai/v1#f\x00", inject.DialectGeneric, "url.Parse alone admits a control byte in the fragment; refused explicitly"},
	{"https://api.x.ai/v1\x7f", inject.DialectGeneric, ""},
	{"https://api.x.ai:443:1/v1", inject.DialectGeneric, "two colons: not a host:port"},
	{"https://attacker.example?@api.x.ai/v1", inject.DialectGeneric, "the query ends the authority in both parsers"},
}

var hostDomainCases = []hostDomainVector{
	{"api.x.ai", "x.ai", true},
	{"x.ai", "x.ai", true},
	{"X.AI.", "x.ai", true},
	{"a.b.x.ai", "x.ai", true},
	{"notx.ai", "x.ai", false},
	{"x.ai.attacker.example", "x.ai", false},
	{"ai", "x.ai", false},
	{"", "x.ai", false},
	{"x.ai", "", false},
	// Dotted capital I: Go's simple fold maps it to "i", JS's full fold to
	// "i" + U+0307, so any non-ASCII input is refused rather than folded.
	{"x.a\xc4\xb0", "x.ai", false},
	{"api.x.ai", "x.a\xc4\xb0", false},
}

var httpsHostCases = []httpsHostVector{
	{"https://api.x.ai/v1", "api.x.ai"},
	{"HTTPS://API.X.AI/v1", "API.X.AI"},
	{"https://gateway.example:8443/v1", "gateway.example"},
	{"http://api.x.ai/v1", ""},
	{"ws://api.x.ai/v1", ""},
	{"https://api.x.ai@attacker.example/v1", ""},
	{"https://api%2ex%2eai/v1", ""},
	{"//api.x.ai/v1", ""},
	{"", ""},
	// url.Parse yields Hostname "::1"; only the LDH check refuses it, and
	// an attested upstream is admitted on this function alone.
	{"https://[::1]:8000/v1", ""},
	{"https://a_b.example/v1", ""},
}

const (
	xaiPosture       = `{"plaintext_terminates":"named_upstream","upstream_base_url":"https://api.x.ai/v1","zero_retention":true}`
	gatewayPosture   = `{"plaintext_terminates":"named_upstream","upstream_base_url":"https://gateway.example/v1","upstream_attested":true}`
	unboundGateway   = `{"plaintext_terminates":"named_upstream","upstream_base_url":"https://gateway.example/v1"}`
	lookalikePosture = `{"plaintext_terminates":"named_upstream","upstream_base_url":"https://api.x.ai.attacker.example/v1","zero_retention":true}`
)

var admissibleCases = []admissibleVector{
	{"xAI with zero retention", xaiPosture, false, true},
	{"xAI with zero retention, attestation also present", xaiPosture, true, true},
	{"xAI without zero retention", `{"plaintext_terminates":"named_upstream","upstream_base_url":"https://api.x.ai/v1"}`, false, false},
	{"xAI over plain http", `{"plaintext_terminates":"named_upstream","upstream_base_url":"http://api.x.ai/v1","zero_retention":true}`, false, false},
	{"xAI over plain http, attestation present", `{"plaintext_terminates":"named_upstream","upstream_base_url":"http://api.x.ai/v1","zero_retention":true}`, true, false},
	{"lookalike host", lookalikePosture, false, false},
	{"userinfo lookalike", `{"plaintext_terminates":"named_upstream","upstream_base_url":"https://api.x.ai@attacker.example/v1","zero_retention":true}`, false, false},
	{"path lookalike", `{"plaintext_terminates":"named_upstream","upstream_base_url":"https://attacker.example/api.x.ai/v1","zero_retention":true}`, false, false},
	{"ACI gateway with attestation", gatewayPosture, true, true},
	{"ACI gateway, block dropped (lapsed appraisal)", gatewayPosture, false, false},
	{"block injected for a node that never signed upstream_attested", unboundGateway, true, false},
	{"upstream_attested over plain http", `{"plaintext_terminates":"named_upstream","upstream_base_url":"http://gateway.example/v1","upstream_attested":true}`, true, false},
	{"attested branch does not consult the vendor: any https host whose enclave the node appraised", `{"plaintext_terminates":"named_upstream","upstream_base_url":"https://api.x.ai.attacker.example/v1","upstream_attested":true}`, true, true},
	{"no URL", `{"plaintext_terminates":"named_upstream"}`, true, false},
	{"in_enclave is not a named upstream", `{"plaintext_terminates":"in_enclave"}`, false, false},
	{"absent posture", "", true, false},
}

var upstreamAttestedCases = []upstreamAttestedVector{
	{`{"protocol":"aci/1","base_url":"https://gateway.example/v1"}`, true, ""},
	{`{"protocol":"aci/1"}`, true, "presence of a recognized protocol is the whole check; nothing else is verified here"},
	{"", false, "absent"},
	{"null", false, ""},
	{"{}", false, "an empty block names no protocol, so it is unverifiable"},
	{`{"protocol":"aci/2"}`, false, "an unrecognized protocol MUST be treated as unverifiable"},
	{`{"protocol":"ACI/1"}`, false, "exact match"},
	{`{"Protocol":"aci/1"}`, false, "keys match exactly on both sides"},
	{`{"protocol":1}`, false, "Go fails the bundle decode; TypeScript reads a non-string"},
	{"[]", false, "not an object: Go fails the bundle decode"},
	{"true", false, ""},
	{`"aci/1"`, false, ""},
}

func buildDialectVectors() dialectVectorsFile {
	return dialectVectorsFile{
		Version: 1,
		Comment: "Cross-impl parity vectors for inferDialect / hostMatchesDomain / httpsUpstreamHost / namedUpstreamAdmissible / upstreamAttested. Expectations are hand-authored. " +
			"Regenerate via: cd proto/go && go test ./inject -run TestDialectVectors -update. " +
			"Loaded by proto/go/inject/dialect_vectors_test.go and proto/ts/test/dialect-vectors.test.ts.",
		InferDialect:     dialectCases,
		HostMatches:      hostDomainCases,
		HTTPSHost:        httpsHostCases,
		Admissible:       admissibleCases,
		UpstreamAttested: upstreamAttestedCases,
	}
}

func TestDialectVectors(t *testing.T) {
	for _, c := range dialectCases {
		if got := inject.InferDialect(c.URL); got != c.Want {
			t.Errorf("InferDialect(%q) = %q, want %q (%s)", c.URL, got, c.Want, c.Why)
		}
	}
	for _, c := range hostDomainCases {
		if got := inject.HostMatchesDomain(c.Host, c.Domain); got != c.Want {
			t.Errorf("HostMatchesDomain(%q, %q) = %v, want %v", c.Host, c.Domain, got, c.Want)
		}
	}
	for _, c := range httpsHostCases {
		got, ok := inject.HTTPSUpstreamHost(c.URL)
		if want := c.Host != ""; ok != want || got != c.Host {
			t.Errorf("HTTPSUpstreamHost(%q) = (%q, %v), want (%q, %v)", c.URL, got, ok, c.Host, want)
		}
	}
	for _, c := range admissibleCases {
		var p *inject.TEEPosture
		if c.PostureJSON != "" {
			p = new(inject.TEEPosture)
			if err := json.Unmarshal([]byte(c.PostureJSON), p); err != nil {
				t.Fatalf("%s: posture does not decode: %v", c.Name, err)
			}
		}
		if got := inject.NamedUpstreamAdmissible(p, c.UpstreamAttested); got != c.Want {
			t.Errorf("NamedUpstreamAdmissible(%s, attested=%v) = %v, want %v", c.Name, c.UpstreamAttested, got, c.Want)
		}
	}
	for _, c := range upstreamAttestedCases {
		doc := "{}"
		if c.BlockJSON != "" {
			doc = `{"upstream_attestation":` + c.BlockJSON + `}`
		}
		// A block Go cannot decode refuses the whole bundle, which is a
		// refusal too; the verdict on the block is then false.
		var b inject.TEEEvidenceBundle
		got := json.Unmarshal([]byte(doc), &b) == nil && inject.UpstreamAttested(b.UpstreamAttestation)
		if got != c.Want {
			t.Errorf("UpstreamAttested(%s) = %v, want %v (%s)", c.BlockJSON, got, c.Want, c.Why)
		}
	}

	encoded, err := json.MarshalIndent(buildDialectVectors(), "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	encoded = append(encoded, '\n')

	if *updateToolGrowthVectors {
		if err := os.WriteFile(dialectVectorsPath, encoded, 0o644); err != nil {
			t.Fatalf("write vectors: %v", err)
		}
		t.Logf("wrote %s", dialectVectorsPath)
		return
	}
	onDisk, err := os.ReadFile(dialectVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(bytes.TrimRight(onDisk, "\n"), bytes.TrimRight(encoded, "\n")) {
		t.Fatalf("%s is stale — regenerate with: cd proto/go && go test ./inject -run TestDialectVectors -update", dialectVectorsPath)
	}
}
