/*
 * Copyright (c) 2026. TxnLab Inc.
 * All Rights reserved.
 */

package attest

import "strings"

// engineConfigForbiddenKeys are the engine-config settings a measured
// deployment may not declare.
//
// WHY THESE TWO AND NOTHING ELSE. The engine config span is LIFTED out of the
// skeleton so an operator can size the runtime for their own hardware —
// context window, sequence count, GPU layers, cache types. Those are choices
// about throughput, and they cannot change what the model says.
//
// These two can:
//
//   - "adapters" attaches LoRA adapters, by id or absolute path. An adapter
//     changes the model's behaviour while every byte of the weights stays
//     exactly what the digest says, so a node could advertise
//     weights_digest_trust=runtime_attested + weights_registry_match=matched
//     and still serve something the attestation never saw. The weights chain
//     has no view of adapters at all — it reports the artifacts the runtime
//     loaded, and an adapter is not one of them.
//   - "template" replaces the jinja chat template, which decides how the
//     conversation is rendered into tokens. It is the same class of problem
//     reached through formatting rather than weights.
//
// So the span is lifted for sizing and closed for behaviour.
//
// Unexported, and returned by value from EngineConfigForbiddenKeys, because an
// exported slice in a security gate is a package global any importer can
// append to or reassign.
var engineConfigForbiddenKeys = []string{"adapters", "template"}

// EngineConfigForbiddenKeys returns the settings an engine-config span may not
// declare. A fresh slice each call: the caller cannot edit the rule.
func EngineConfigForbiddenKeys() []string {
	out := make([]string, len(engineConfigForbiddenKeys))
	copy(out, engineConfigForbiddenKeys)
	return out
}

// EngineConfigViolations returns the forbidden keys a compose's engine-config
// spans declare, in the order EngineConfigForbiddenKeys lists them. Empty means
// the document is acceptable.
//
// IT SCANS THE SPANS THE SKELETON LIFTED, taken straight from
// ExtractComposeSpans, and never re-walks the document. The reason is on
// ExtractComposeSpans: a second walk disagreed with the lift in three ways, and
// each disagreement was a forbidden key riding in text nothing checked.
//
// A DOCUMENT THAT CANNOT BE TAKEN APART IS A VIOLATION, not an absence. This is
// the same rule ComposePolicy.check applies to the skeleton, and it matters
// more here: the content rule runs even when EnforceComposeSkeleton is off, so
// under the shipped policy it is the only thing looking at this document. A tab
// anywhere in the file used to make the walk report "no span" and produce no
// violations at all.
func EngineConfigViolations(dockerCompose string) []string {
	if isBlank(dockerCompose) {
		return nil
	}
	_, _, bodies, err := ExtractComposeSpans(dockerCompose)
	if err != nil {
		// A refusal here means the walk never reached the spans, so this rule
		// cannot say the document is clean. But it may only blame the ENGINE
		// CONFIG for a document that has one: a compose that declares no image
		// is malformed for reasons the skeleton path reports far better, and
		// answering it with "your engine config is wrong" sends the operator
		// somewhere there is nothing to find.
		//
		// The test is a substring, not a walk — a document with no sentinel
		// anywhere cannot contain a span, since the lift requires that exact
		// key. Conservative in the direction that matters: a malformed document
		// that DOES mention it is refused.
		if strings.Contains(dockerCompose, ComposeEngineConfigKey) {
			return []string{"unparseable-compose"}
		}
		return nil
	}

	var found []string
	for _, key := range engineConfigForbiddenKeys {
		for _, body := range bodies {
			if engineConfigMentions(body, key) {
				found = append(found, key)
				break
			}
		}
	}
	return found
}

// engineConfigMentions reports whether a lifted span mentions a forbidden key
// at all.
//
// A CASE-INSENSITIVE SUBSTRING TEST, DELIBERATELY, and the bluntness is the
// point. An earlier version tried to recognise the key in the positions a YAML
// mapping key can occupy — start of a trimmed line, or after `{` or `,`. Every
// one of these is also a legal way to write the same key, and all of them
// walked straight through it:
//
//	adapters : [x]          a space before the colon; YAML drops it
//	adapters\t: [x]         a tab, likewise
//	- adapters: [x]         a block-sequence entry
//	m: [adapters: [x]]      a flow sequence of single-pair maps
//	"\x61dapters": [x]      a double-quoted hex escape, schema-independent
//	? adapters              an explicit key
//
// Enumerating key positions means enumerating YAML, which is the thing this
// package refuses to do in front of a security question — the same argument
// ExtractComposeSkeleton's godoc makes about parsers disagreeing. A substring
// test has no positions to miss.
//
// It over-refuses, including on a comment that merely mentions the word, and
// that is the accepted cost: the span is a short machine-written config, the
// refusal is loud and names the key, and the opposite error is invisible to
// every other check in the chain.
func engineConfigMentions(body, key string) bool {
	return strings.Contains(strings.ToLower(body), key)
}
