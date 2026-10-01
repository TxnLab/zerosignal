/*
 * Copyright (c) 2026. TxnLab Inc.
 * All Rights reserved.
 */

package attest

import "testing"

// The two codepoints where Go's and JavaScript's built-in whitespace notions
// disagree.
//
// COMPUTED FROM THEIR NUMBERS, never written as characters or even as string
// escapes. Both are invisible in an editor, and a literal U+FEFF is not a
// character to the Go scanner at all — it rejects the whole file with "illegal
// byte order mark", which is how the first draft of this file failed. Building
// them arithmetically keeps every byte of the source visible and reviewable.
var (
	// wsNEL is whitespace to Go's unicode.IsSpace and not to JS's trim.
	wsNEL = string(rune(0x0085))
	// wsBOM is the reverse: whitespace to JS's trim, not to Go's.
	wsBOM = string(rune(0xFEFF))
)

// TestUnicodeWhitespace_DoesNotMoveAnyVerdict is the regression pin for a
// divergence that shipped, and that this suite could not see.
//
// Every whitespace decision in compose.go used to be strings.TrimSpace and
// every one in compose.ts used String.prototype.trim. Those are NOT the same
// predicate, and the difference was load-bearing at eleven call sites.
// Measured consequences, in BOTH directions: a docker_compose_file of one
// U+0085 was empty_docker_compose in Go and ACCEPTED in TS, one U+FEFF was the
// reverse, and either character trailing an image reference or sitting on a
// line inside the config block moved the skeleton digest on one side only.
//
// It mattered more than a cosmetic split. empty_docker_compose is the ONLY
// rule guarding docker_compose_file while both consumers ship
// EnforceComposeSkeleton false, so this was a live fail-open on
// adversary-chosen bytes — the vacuous-measurement shape this package exists
// to refuse.
//
// What is pinned here is the PROPERTY, not the fix: neither codepoint may
// change any verdict, in either implementation. The identical table runs in
// proto/ts/test/attest-compose.test.ts, and neither copy is evidence without
// the other — a single-language test of a cross-language predicate agrees with
// itself by construction.
func TestUnicodeWhitespace_DoesNotMoveAnyVerdict(t *testing.T) {
	cases := map[string]string{"nel": wsNEL, "bom": wsBOM}

	t.Run("both are an empty docker_compose", func(t *testing.T) {
		// This assertion was originally the other way round — "neither
		// reports empty" — on the reasoning that either answer was
		// defensible so long as the two languages agreed. Making them
		// agree was necessary and not sufficient: the golden vectors
		// then showed them agreeing on the WRONG answer, because a
		// compose of one invisible character sailed past
		// empty_docker_compose, which is the only rule guarding
		// docker_compose_file while consumers ship
		// EnforceComposeSkeleton false. One character disabled it.
		//
		// So the vacuous-compose test is `isBlank`, the union of both
		// languages' whitespace notions, and it is deliberately the
		// opposite extreme from trimASCII — see compose.go. Everything
		// that could be nothing counts as nothing.
		for name, c := range cases {
			doc := `{"manifest_version":2,"runner":"docker-compose",` +
				`"docker_compose_file":"` + c + `"}`
			_, err := VerifyAppCompose(doc, sealed(doc), ComposePolicy{})
			if !hasCodeIn(err, ViolationEmptyDockerCompose) {
				t.Errorf("a %s-only compose is not reported as empty, so one "+
					"invisible character sidesteps the only rule guarding "+
					"docker_compose_file: %v", name, err)
			}
		}
	})

	t.Run("both languages compute the same skeleton digest", func(t *testing.T) {
		// The first draft of this asserted the digest does NOT move,
		// and that premise was wrong: an unindented line ends the
		// block scalar under YAML's own rule, so it correctly leaves
		// the elided span and becomes skeleton text. The digest SHOULD
		// move.
		//
		// Which means the property worth pinning was never "unchanged"
		// — it is "the same on both sides", and that cannot be checked
		// from inside one language. So these are pinned as literals
		// the TS twin asserts against, the same mechanism
		// goSkeletonDigestFixture already uses. A divergence shows up
		// as one suite red and the other green.
		want := map[string]string{
			"nel": "fea9251a8b5dbdeb893c972b1e496ce3f4b8c1d75c89e7b6fea26b46a4e072f6",
			"bom": "b93c12b1ec0e7d598ac3e51d98d3604b3f634285580d8b728c289334cada8598",
		}
		for name, c := range cases {
			skel, _, err := ExtractComposeSkeleton(
				realisticCompose(realImage, someConfig+c+"\n"))
			if err != nil {
				t.Fatalf("%s: extract: %v", name, err)
			}
			if got := ComposeSkeletonDigest(skel); got != want[name] {
				t.Errorf("skeleton digest with a trailing %s = %s, pinned %s\n\n"+
					"If this moved deliberately, update BOTH this map and the one "+
					"in proto/ts/test/attest-compose.test.ts — updating one leaves "+
					"each implementation agreeing with itself and not the other, "+
					"which is the exact failure this test exists for.",
					name, got, want[name])
			}
		}
	})

	t.Run("neither is trimmed off an image reference", func(t *testing.T) {
		for name, c := range cases {
			_, ref, err := ExtractComposeSkeleton(
				realisticCompose(realImage+c, someConfig))
			if err != nil {
				t.Fatalf("%s: extract: %v", name, err)
			}
			if ref == realImage {
				t.Errorf("a trailing %s was trimmed away, so this reference matches "+
					"TrustedNodeImages here while TS reads it as a different image",
					name)
			}
		}
	})

	t.Run("neither is trimmed out of an env name", func(t *testing.T) {
		// The env allowlist is the rule the package's own comments
		// call the most load-bearing, and it is a set membership on a
		// trimmed, upper-cased name — so a trim that differs is a
		// membership that differs.
		pol := ZeroSignalComposePolicy()
		for name, c := range cases {
			doc := `{"manifest_version":2,"runner":"docker-compose",` +
				`"docker_compose_file":"services: {}\n",` +
				`"allowed_envs":["` + ZeroSignalSecretEnvNames()[0] + c + `"]}`
			_, err := VerifyAppCompose(doc, sealed(doc), pol)
			if !hasCodeIn(err, ViolationEnvNotAllowed) {
				t.Errorf("a permitted env name with a trailing %s was accepted here; "+
					"TS reads it as a different name and refuses it", name)
			}
		}
	})
}
