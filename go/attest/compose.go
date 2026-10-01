/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// app-compose validation
// ---------------------------------------------------------------------------
//
// dstack hashes a JSON document — its `app-compose.json` — into RTMR3 as the
// `compose-hash` runtime event. Allowlisting that hash does not scale: every
// operator and every redeploy produces a distinct one, so a relying party would
// need a curated entry per deployment. Worse, a hash allowlist is only ever as
// good as a human having read the document behind it, and a compose can measure
// nothing at all — our own probe compose pins `image: ${PROBE_IMAGE}`, which is
// a stable hash over arbitrary code.
//
// So this package validates the CONTENT instead. The preimage is recoverable
// in band: `sha256(tcb_info.app_compose) == compose_hash` exactly, measured on
// a live Phala tdx.small CVM 2026-08-28, and the full document already rides
// the guest agent's /Info response. Check the hash against the REPLAYED event
// log first, then read fields off a document that is now known to be the one
// the hardware measured.
//
// The remaining allowlist is per-RELEASE, not per-deployment — the same shape a
// measurement transparency log would hold.

// Errors from VerifyAppCompose. Each is a sentinel because each names a branch
// that fails OPEN under a plausible edit: returning the parsed document with a
// nil error hands a verifier fields it never checked the provenance of.
var (
	// ErrNoComposeHash means the replayed event log carried no compose-hash
	// event, so there is nothing to check the document against.
	//
	// Distinct from a mismatch on purpose. Treating "absent" as "skip" is the
	// whole vulnerability: a node that simply omits the event would validate
	// against nothing while every field below still reports clean.
	ErrNoComposeHash = errors.New("attest: event log carried no compose-hash")

	// ErrNoAppCompose means the bundle published no app-compose document.
	//
	// An empty preimage still hashes to a well-formed digest, so this must
	// fail before the comparison rather than hash "" and report a mismatch —
	// the two are different findings and only one of them is the operator's
	// fault.
	ErrNoAppCompose = errors.New("attest: bundle carried no app_compose")

	// ErrComposeHashMismatch means the published document is not the one the
	// hardware measured. Nothing below it means anything.
	ErrComposeHashMismatch = errors.New("attest: app_compose does not hash to the measured compose-hash")

	// ErrAppComposeMalformed means the document did not parse as the
	// app-compose shape at all.
	ErrAppComposeMalformed = errors.New("attest: app_compose is not a well-formed app-compose document")
)

// AppCompose is dstack's app-compose.json, the document hashed into RTMR3.
//
// Field set captured from a live Phala tdx.small CVM (dstack-0.5.9,
// manifest_version 2). Unknown fields are a POLICY VIOLATION rather than
// something to ignore — see ViolationUnknownField.
type AppCompose struct {
	ManifestVersion int      `json:"manifest_version"`
	Name            string   `json:"name"`
	Runner          string   `json:"runner"`
	DockerCompose   string   `json:"docker_compose_file"`
	PreLaunchScript string   `json:"pre_launch_script"`
	AllowedEnvs     []string `json:"allowed_envs"`
	Features        []string `json:"features"`

	GatewayEnabled  bool `json:"gateway_enabled"`
	TProxyEnabled   bool `json:"tproxy_enabled"`
	KMSEnabled      bool `json:"kms_enabled"`
	LocalKeyProvide bool `json:"local_key_provider_enabled"`
	NoInstanceID    bool `json:"no_instance_id"`
	SecureTime      bool `json:"secure_time"`
	PublicLogs      bool `json:"public_logs"`
	PublicSysinfo   bool `json:"public_sysinfo"`
	PublicTCBInfo   bool `json:"public_tcbinfo"`

	StorageFS string `json:"storage_fs"`
}

// knownAppComposeFields is the exact top-level key set this package models.
//
// It exists because "I validated the fields I know about" is not "I validated
// the document". A dstack release that adds a top-level key — another boot
// hook, another key-delivery channel — would otherwise ride through every check
// below reporting clean, and the failure would be invisible in both logs.
// BEING LISTED HERE SUPPRESSES unknown_field, so a key that is listed and
// never read is worse than one that is missing: it rides through silently
// where an unmodelled key would at least have been reported. `features` and
// `storage_fs` were exactly that until AllowedFeatures / StorageFS were added
// to ComposePolicy below.
//
// `name` is the one deliberate exception. It is the operator's own label for
// the deployment, carries no capability, and pinning it would refuse every
// node that did not copy our example verbatim. Read that as "checked and
// dismissed", not as an oversight.
var knownAppComposeFields = map[string]bool{
	"allowed_envs": true, "docker_compose_file": true, "features": true,
	"gateway_enabled": true, "kms_enabled": true, "local_key_provider_enabled": true,
	"manifest_version": true, "name": true, "no_instance_id": true,
	"pre_launch_script": true, "public_logs": true, "public_sysinfo": true,
	"public_tcbinfo": true, "runner": true, "secure_time": true,
	"storage_fs": true, "tproxy_enabled": true,
}

// ---------------------------------------------------------------------------
// Violations
// ---------------------------------------------------------------------------

// ViolationCode names a class of policy failure. Stable strings, because both
// a Go proxy and a browser client surface them and a renumbering would silently
// change what a UI says.
type ViolationCode string

const (
	ViolationUnknownField       ViolationCode = "unknown_field"
	ViolationManifestVersion    ViolationCode = "manifest_version"
	ViolationRunner             ViolationCode = "runner"
	ViolationRootBackdoorEnv    ViolationCode = "root_backdoor_env"
	ViolationEnvNotAllowed      ViolationCode = "env_not_allowed"
	ViolationPreLaunchScript    ViolationCode = "pre_launch_script"
	ViolationToggle             ViolationCode = "toggle"
	ViolationEmptyDockerCompose ViolationCode = "empty_docker_compose"
	ViolationComposeSkeleton    ViolationCode = "compose_skeleton"
	ViolationNodeImage          ViolationCode = "node_image"
	ViolationFeature            ViolationCode = "feature"
	ViolationStorageFS          ViolationCode = "storage_fs"
	// ViolationEngineConfigKey refuses an engine-config span that declares a
	// setting able to change what the model SAYS rather than how fast it says
	// it. Checked here, on the payer's side, because a node-side check protects
	// an honest operator from a mistake and protects a payer from nothing — the
	// operator running a patched binary simply does not run it.
	ViolationEngineConfigKey ViolationCode = "engine_config_key"
	// ViolationPolicyMisconfigured is about the VERIFIER, not the node.
	// Every other code here says the operator did something; this one says
	// the reference data and the flag that switches it on disagree, so the
	// check the verifier believes it is running is not running.
	ViolationPolicyMisconfigured ViolationCode = "policy_misconfigured"
)

// Violation is one policy failure, named specifically enough that an operator
// can act on it without reading this file.
type Violation struct {
	Code   ViolationCode
	Detail string
}

func (v Violation) String() string { return string(v.Code) + ": " + v.Detail }

// Exemption is a rule that WOULD have failed and was downgraded because the
// policy named it — today only ViolationRootBackdoorEnv, via
// ComposePolicy.AllowedRootBackdoorEnvs.
//
// It is a distinct type from Violation rather than a Violation with a flag,
// because the two must never be summed. A verifier reporting "0 violations"
// over a document with exemptions has told the truth and communicated the
// opposite; keeping them in different slices means the honest sentence is the
// one that falls out of the shape.
type Exemption struct {
	Code   ViolationCode
	Detail string
	// Subject is the one thing that was conceded — for
	// ViolationRootBackdoorEnv, the env name. It exists separately from
	// Detail because the two have different readers: Detail is prose for an
	// operator's log, Subject is what a machine matches on.
	Subject string
}

func (e Exemption) String() string { return string(e.Code) + ": " + e.Detail }

// WireTag is the normative `<rule>:<detail>` form SPEC § 3e pins for the
// published upstream_attestation.carve_outs list.
//
// DELIBERATELY NOT String(). A payer's verifier is specified to read these —
// `root_backdoor_env:DSTACK_ROOT_PUBLIC_KEY` is a token it can compare against
// its own expectation — and String() carries a sentence of operator-facing
// prose after the code. Publishing that reads as a well-formed carve-out no
// verifier matches, so the honesty field ends up honest and unusable at the
// same time. Falls back to Detail when there is no Subject rather than
// emitting a bare code, so a future exemption whose subject nobody filled in
// still names something.
func (e Exemption) WireTag() string {
	if e.Subject != "" {
		return string(e.Code) + ":" + e.Subject
	}
	return string(e.Code) + ":" + e.Detail
}

// ComposePolicyError carries every violation found.
//
// VerifyAppCompose returns violations THROUGH the error rather than as a second
// value, deliberately. A `(doc, violations, error)` signature fails open under
// the most natural caller there is — `if err != nil { reject }` — which accepts
// a document with a full slice of findings and a nil error. There is no way to
// write that bug against this shape.
type ComposePolicyError struct {
	Violations []Violation
}

func (e *ComposePolicyError) Error() string {
	parts := make([]string, 0, len(e.Violations))
	for _, v := range e.Violations {
		parts = append(parts, v.String())
	}
	return "attest: app_compose violates policy [" + strings.Join(parts, "; ") + "]"
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

// ComposePolicy is the set of content rules a relying party enforces.
//
// Every field is data rather than a hardcoded constant so the proxy and the
// browser client run the SAME implementation over a list each can update on its
// own release cadence — the split `proto/go/selection` uses for the same
// reason.
type ComposePolicy struct {
	// ManifestVersion the document must declare. Zero disables the check.
	ManifestVersion int

	// Runner the document must declare, e.g. "docker-compose". Empty
	// disables the check.
	Runner string

	// AllowedEnvNames is the set of environment variable NAMES the compose
	// may declare, matched case-insensitively.
	//
	// dstack injects only names listed in the document's allowed_envs, so
	// this set is what stops the unmeasured env channel being a general
	// config-override path. Measured 2026-08-28: adding a NAME moves
	// compose_hash, changing a VALUE does not — which is exactly the split
	// that makes this rule enforceable remotely while a secret still rotates
	// without re-attesting.
	//
	// A nil set means the membership check does not run. That is a widening,
	// so it is deliberately not the same thing as an empty set, which
	// forbids every name — see enforceEnvAllowlist.
	AllowedEnvNames []string

	// AllowedEnvSuffixes permits a name by its SUFFIX, matched
	// case-insensitively, for the one secret channel whose names a policy
	// cannot enumerate: proto/go/keystore loads every `<ANYTHING>_MNEMONIC`
	// in the environment, so the prefix is operator-chosen by design.
	//
	// Kept deliberately narrow, and it is worth being clear about why a
	// suffix is safe here when a prefix rule would not be. A name grants
	// power only through what reads it. The node's applyEnv reads ~119
	// distinct `NODE_*` names, so `NODE_*` is a config-override surface and
	// permitting it wholesale would let the unmeasured channel rewrite the
	// measured document. `*_MNEMONIC` is read only by the keystore, which
	// treats the value as key material and the name as a label — there is no
	// setting to reach through it.
	//
	// A suffix that is empty or does not begin with "_" is IGNORED rather
	// than matched: "" would permit every name, and a bare-word suffix would
	// match any name ending in those letters. Both are the fail-open shape.
	AllowedEnvSuffixes []string

	// EnforceEnvAllowlist selects between those two readings of a nil/empty
	// AllowedEnvNames. It exists so "allow everything" can only ever be
	// reached by writing it down: an empty list read as "no constraint" is
	// the fail-open shape this whole package is built to avoid.
	EnforceEnvAllowlist bool

	// AllowedRootBackdoorEnvs downgrades named RootBackdoorEnvs entries from
	// a violation to a recorded exception, for the ONE case where the
	// document under appraisal is not ours: a third-party attested UPSTREAM.
	//
	// EMPTY IS THE ONLY CORRECT VALUE FOR A ZEROSIGNAL NODE, and
	// ZeroSignalComposePolicy leaves it nil — pinned by a test, because the
	// obvious tidying-up is to wire the two together and that would silently
	// let an operator exempt their own node from the check the whole package
	// exists to run. AllowedEnvNames cannot serve here: a root credential is
	// not a finding of the same kind as an unexpected name, which is why the
	// backdoor check deliberately sits outside that allowlist.
	//
	// WHAT AN ENTRY HERE CONCEDES, stated so a caller cannot take it for
	// less. dstack measures env NAMES and not VALUES, so the compose hash is
	// identical whether or not a key was supplied: the channel is visible,
	// its use is not. And RTMR3 records BOOT, not runtime — someone with a
	// shell changes what the container runs and no measurement moves, so
	// every other rule in this policy keeps passing on code that is no
	// longer the code that was measured. An exemption here therefore does
	// not weaken one rule, it caps what a clean result from all of them
	// means.
	//
	// A caller cannot take an exemption quietly. VerifyAppCompose REFUSES a
	// policy that sets this (ViolationPolicyMisconfigured); only
	// VerifyUpstreamAppCompose honours it, and that one hands the exemptions
	// back as a second return value the caller has to receive. The exemption
	// is meant to travel to the payer, not stop here.
	//
	// IT IS NOT HONOURED ON ITS OWN. RootBackdoorSafeOSImages below gates it,
	// because the concession is only defensible on a guest image where the
	// channel has no consumer.
	AllowedRootBackdoorEnvs []string

	// RootBackdoorSafeOSImages are the `os-image-hash` values on which an
	// AllowedRootBackdoorEnvs concession may be honoured: guest images
	// verified to ship NO SSH daemon, so the env writes an authorized_keys
	// file that nothing reads.
	//
	// IT EXISTS BECAUSE THE CONCESSION AND ITS JUSTIFICATION LIVED IN
	// DIFFERENT PLACES, and only one of them was checked. The concession is
	// defensible today for exactly one reason: `dstack-0.5.9` contains no
	// sshd, dropbear, tinyssh, getty or login — established 2026-09-25 by
	// enumerating the squashfs directory table of the rootfs the measured
	// `os-image-hash` transitively pins (it is sha256(sha256sum.txt), which
	// commits to metadata.json, which carries the dm-verity root hash). That
	// is a property of an IMAGE. Without this field the concession was a
	// property of the POLICY, honoured against whatever image happened to
	// boot — so adding a digest to the caller's trusted-image list silently
	// extended a root-shell carve-out to it, in an edit that looked like it
	// was only about which images are recognized, reviewed by someone with no
	// reason to be thinking about root shells.
	//
	// EMPTY HONOURS NOTHING, matching node's and proxy's TrustedOSImages
	// fields rather than the allow-everything reading (the list this package
	// exports is TrustedDstackOSImages; the consumers hold it in a field of
	// that name): a caller that names a concession but no image
	// to honour it on gets the strict rule and a refusal. That is the
	// correct direction — the failure mode of the other choice is admitting a
	// node whose image ships an sshd.
	//
	// THE SET IS NARROWER THAN A TRUSTED-IMAGE LIST AND MUST STAY SO. Trusting
	// an image says its measurement maps to a published production artifact;
	// naming it here says someone enumerated its filesystem and found no way
	// to consume an authorized_keys file. The second does not follow from the
	// first, so the two lists are separate even when their contents coincide,
	// and a new dstack release joins TrustedDstackOSImages without joining
	// this until the scan is run (plans/future/tee/phala-revalidation-2026-09-25.md
	// § 9.4 step 5 is the procedure; assert the control names, or a broken
	// enumeration reads as a clean pass).
	//
	// DELIBERATELY NOT OPERATOR-CONFIGURABLE, and the asymmetry with
	// AllowedRootBackdoorEnvs is the point. That one comes from an operator's
	// config (node: tee.upstream_attestation.allow_root_backdoor_env), because
	// conceding a rule is a choice a deployment gets to make and publish. This
	// one is a claim about a filesystem somebody read, so an operator who could
	// widen it could hand themselves the concession they are meant to be
	// declaring — the node path feeds ACIUpstreamComposePolicy from config for
	// the first and from the compiled-in list for the second.
	//
	// WHAT IT STILL DOES NOT ESTABLISH: `/dstack/user_config`'s
	// `ssh_authorized_keys` rides no measured field, so neither this nor an
	// absent env name is evidence that no root key was provisioned. It is
	// evidence that a declared channel has no consumer on this image.
	RootBackdoorSafeOSImages []string

	// PreLaunchScriptDigests is the set of sha256 digests (lowercase hex) the
	// pre-launch script may have.
	//
	// Phala's own script is ~17 KB of bash that runs as root before the
	// container, and it is what writes DSTACK_AUTHORIZED_KEYS to root's
	// authorized_keys. It is measured, but measured only means "you can tell
	// which one" — pinning is what makes that useful. An EMPTY script is
	// always accepted; anything else must be a digest a release blessed.
	//
	// AN EMPTY LIST THEREFORE PERMITS ONLY AN EMPTY SCRIPT — it is the
	// strictest setting, not the absent one. That is the opposite of how a
	// list usually reads, which is why it has no EnforcePreLaunch twin:
	// there is no way to spell "any boot hook is fine", because there is no
	// legitimate reason to want it. Compare AllowedEnvNames, where an
	// unconstrained setting IS legitimate during a migration and so had to be
	// spellable, and therefore had to be made explicit.
	PreLaunchScriptDigests []string

	// Toggles pins the document's boolean switches. A nil entry reports
	// nothing, so a switch whose correct value is genuinely unsettled stays
	// visibly unpinned rather than being pinned to a guess.
	Toggles ComposeToggles

	// TrustedComposeSkeletons is the set of sha256 digests (lowercase hex) of
	// published release compose SKELETONS — see ExtractComposeSkeleton.
	//
	// This is the rule that makes content validation mean anything. Without
	// it a compose pinning `image: ${SOME_VAR}` holds a perfectly stable
	// compose_hash over arbitrary code and satisfies every other field here.
	TrustedComposeSkeletons []string

	// TrustedNodeImages is the set of published zs-node image references the
	// compose may run, compared verbatim (`ghcr.io/…@sha256:…`).
	//
	// It judges the FIRST `image:` in the document and no other. On a
	// single-service compose that is the only one; on the sealed_local sidecar
	// shape the later images are pinned by the skeleton instead, and are
	// required to be digest-pinned so that pin means something.
	//
	// So "the node's image" is a release-authoring convention the extractor
	// cannot know. A document that puts another service first hands this check
	// that service's reference, which is not on this list, so it is refused —
	// which makes the convention self-enforcing FOR A GIVEN release, but not
	// across releases. Publish a multi-image release that lists an engine
	// first and that engine's reference has to go on this list; from then on
	// it would satisfy some other release's node-image hole, which is the
	// released-engine-passes-as-released-node confusion the lifting rule
	// avoids. Keep the node's `image:` first in every published skeleton.
	//
	// Verbatim and not digest-only on purpose: a digest alone would accept
	// the right bytes served from any registry path, and the repository half
	// is what says these bytes are the ones CI published.
	TrustedNodeImages []string

	// EnforceComposeSkeleton selects between the two readings of empty
	// TrustedComposeSkeletons / TrustedNodeImages lists, exactly as
	// EnforceEnvAllowlist does and for the same reason: these are
	// per-RELEASE data that each consumer ships on its own cadence, so an
	// empty list read as "no constraint" would silently disable the check
	// on any build whose list had not been populated yet.
	//
	// With it set, an empty list refuses everything. That is the correct
	// fail-closed direction and matches trusted_os_images: a verifier with
	// no reference does not verify, it does not wave things through.
	//
	// The flag closes the empty-list reading and opens a NEW one, which is
	// why check() reports ViolationPolicyMisconfigured when the lists are
	// populated and this is false: that state performs no check and is
	// indistinguishable from a correct build, so a verifier shipping the
	// data and forgetting the switch would look exactly like one that meant
	// to leave it off. A misconfigured verifier is a finding, not a skip.
	EnforceComposeSkeleton bool

	// AllowedFeatures is the `features` set the document may declare.
	//
	// EMPTY MEANS UNCHECKED here, unlike PreLaunchScriptDigests, and the
	// asymmetry is deliberate rather than an inconsistency. An empty
	// pre-launch list permits only an empty script because there is no
	// legitimate reason to want an arbitrary root boot hook. dstack, by
	// contrast, declares features on every real deployment — the 2026-08
	// capture carries `kms` and `tproxy-net` — so "empty means only empty"
	// would refuse every honest node, and a rule that cannot ship is worth
	// less than one that can be switched off.
	//
	// The residual risk is the same shape as PreLaunchScriptDigests': a
	// dstack release that adds a feature refuses nodes using it until this
	// list moves. That is why it is a field and not a constant.
	AllowedFeatures []string

	// StorageFS pins the encrypted-filesystem backend. Empty means
	// unchecked, because the correct value is genuinely unsettled across
	// dstack releases — the field exists so the choice is visible rather
	// than silently unmade.
	StorageFS string

	// rootBackdoorWithheldOn records that verifyAppCompose dropped a
	// root-backdoor concession because the guest image was not on
	// RootBackdoorSafeOSImages. It holds the observed os-image-hash, or
	// "(absent)" when the replay carried none. rootBackdoorWithheld holds the
	// names that were dropped, because the sharper message is only correct for
	// a name the policy actually conceded — a document naming a DIFFERENT
	// backdoor channel was never exempted and must still read as the plain
	// refusal.
	//
	// UNEXPORTED, AND SET ONLY ON verifyAppCompose'S BY-VALUE COPY. It exists
	// for one reason: without it the refusal an operator sees is an ordinary
	// root_backdoor_env violation, identical to the one they get for setting
	// no concession at all. They have already set allow_root_backdoor_env,
	// the node exits at boot, and the obvious next move from that message is
	// to widen the concession — the wrong direction, when the actual cause is
	// that nobody has enumerated that image's filesystem. Naming the image in
	// the message is what makes the precondition discoverable at the moment
	// it bites.
	rootBackdoorWithheldOn string
	rootBackdoorWithheld   []string
}

// ComposeToggles pins app-compose's boolean switches. nil means "not checked".
type ComposeToggles struct {
	GatewayEnabled  *bool
	TProxyEnabled   *bool
	KMSEnabled      *bool
	LocalKeyProvide *bool
	NoInstanceID    *bool
	SecureTime      *bool
	PublicLogs      *bool
	PublicSysinfo   *bool
	PublicTCBInfo   *bool
}

// RootBackdoorEnvs are the env names that hand the operator a root shell in a
// CVM whose attestation says nobody has one.
//
// These are checked regardless of AllowedEnvNames and reported under their own
// code, because "unknown env name" and "the operator installed a root key" are
// not findings of the same severity and an operator reading the second one
// needs to know which it is.
//
// DSTACK_AUTHORIZED_KEYS is not hypothetical: `phala deploy` appends it
// silently, from the first of ~/.ssh/{id_rsa,id_ed25519,id_ecdsa,id_dsa}.pub
// that exists, unless --no-dev-os is passed. No prompt, no output. The only
// visible trace is this name appearing in allowed_envs, which is how it was
// found in the first place.
func RootBackdoorEnvs() []string {
	return []string{
		"DSTACK_AUTHORIZED_KEYS",
		"DSTACK_ROOT_PUBLIC_KEY",
		"DSTACK_ROOT_PASSWORD",
	}
}

// PhalaPreLaunchDigests are the pre-launch scripts a ZeroSignal verifier
// recognizes: the script measured on the 2026-08-25 tdx.small capture (17059
// bytes, self-identifying as v0.0.19) and the one measured on the 2026-09-02
// GPU capture (17569 bytes, v0.0.20).
//
// THE PREDICTION BELOW CAME TRUE IN EIGHT DAYS, which is the useful thing to
// know about this list's cadence. Nothing announced v0.0.20; it arrived under a
// CVM we deployed, and the only reason it did not de-route that node is that
// nobody was routing to it yet.
//
// AN EARLIER VERSION OF THIS COMMENT SAID THESE ARE "shipped by known phala CLI
// releases". That is false, and the correction matters because it changes who
// controls the value. The script is NOT in the CLI — `grep -rl
// 'home/root/.ssh' package/` over phala@1.1.21 finds nothing. The Phala Cloud
// API injects it server-side at deploy time, so its digest moves on Phala's
// schedule, with no version to track, no release note, and nothing an
// npm-based sweep could enumerate. Verified 2026-08-29.
//
// THE CONSEQUENCE IS OPERATIONAL AND THE REASON THIS LIST NEEDS AN OVERRIDE.
// The rule is unconditional — it fires today, on nodes that publish a
// preimage, regardless of EnforceComposeSkeleton — so the first time Phala
// edits their template, every newly deployed node is refused with
// measurement_mismatch while behaving perfectly. A relying party therefore
// needs a way to add a digest without waiting on a release of ours: the proxy
// exposes zs.tee.trusted_pre_launch_digests for exactly that, and node
// operators can read their own value off /v1/zs/attestation (see
// node/docs/tee.md).
//
// Widening this list by guessing is not an option — a digest admitted here
// blesses 17KB of root-privileged bash sight unseen, so an entry must come
// from a script someone has actually read.
//
// v0.0.20 was read in full and diffed against v0.0.19 before being added, and
// it grants NOTHING new. The delta is a hardening pass for being sourced under
// `set -u`: most hunks wrap a bare "$VAR" as "${VAR-}", one initializes the
// locals in the fingerprint helper for the same reason, two reflow a
// multi-line pipeline onto one line, one rewrites `tr -d '"'"'"` as two `tr`
// calls over the same two-character set, and one bumps the version echo.
//
// THREE hunks change behavior, and all three narrow rather than widen:
// DOCKER_REGISTRY_TARGET moves out of the docker-credentials branch (the GHCR
// block below referenced it unbound otherwise), the app-compose.json read
// gains an `[[ -f … ]]` guard, and the DSTACK_APP_DOMAIN export now also
// requires a non-empty DSTACK_APP_ID. The count is spelled out because an
// enumeration is what spares the next reader from re-deriving 17KB of bash,
// and an enumeration that is merely nearly complete is worse than none.
//
// Every root-privileged operation is byte-identical: the same root-password
// paths, and the same three SSH-key channels — DSTACK_ROOT_PUBLIC_KEY,
// DSTACK_AUTHORIZED_KEYS, and `ssh_authorized_keys` in the host-provisioned
// /dstack/user_config. The first two are why RootBackdoorEnvs exists; the
// third is reachable via `phala deploy --ssh-pubkey`, rides no measured field,
// and is therefore something this policy cannot see (node/docs/tee.md item 4
// says so to operators).
func PhalaPreLaunchDigests() []string {
	return []string{
		"cec8f68ce6185b912023d886bba20cd06386dd9751af904e6107e758b9d68983",
		"982181610f70be9087b1c69b36b719b47b82d37fcef8acc9289ed3bb3095ffe8",
	}
}

// ZeroSignalSecretEnvNames are the exact environment variable names a ZeroSignal
// node deployment may declare in the unmeasured channel, alongside the
// `*_MNEMONIC` suffix (see ZeroSignalComposePolicy).
//
// EVERY ONE OF THESE CARRIES A CREDENTIAL AND NOTHING ELSE. That is the
// membership rule, and the reason the list is short in a namespace that is not:
// the node's applyEnv reads ~119 distinct `NODE_*` names, and all but these are
// configuration. Since applyEnv runs AFTER the measured NODE_CONFIG_YAML is
// unmarshalled, a name outside this list is an unmeasured override of the
// measured document — `NODE_LLM_OPENAI_BASE_URL` redirects the one upstream the
// rung-1 claim names, `NODE_TEE_DATAFLOW` rewrites the claim itself. Neither
// moves compose_hash once the name is declared, because dstack measures the
// name and not the value.
//
// So this list is what makes "the configuration is inside the measurement" true
// rather than nearly true, and adding a name to it is a decision about what an
// operator may change after attestation — not a convenience.
func ZeroSignalSecretEnvNames() []string {
	return []string{
		"NODE_LLM_OPENAI_API_KEY",
		"NODE_IMAGE_LLM_OPENAI_API_KEY",
		"NODE_LLM_COMFYUI_CLOUD_API_KEY",
		// Cloud secret references, not secrets — the URLs name a
		// secret manager. Still a credential channel, still no
		// configuration reachable through it.
		"ZS_MNEMONIC_URLS",
		// The algod bearer token. It is read by applyEnv like every
		// other NODE_* name, but it is a CREDENTIAL and the value
		// reaches nothing configurable — which is the membership rule
		// above, and it was simply missed. Its absence had a cost:
		// an operator on a token-authenticated algod had to inline the
		// token into NODE_CONFIG_YAML, which since 9.6 the node serves
		// unauthenticated to anyone who asks, or be refused outright.
		// "Publish your token or don't run" is not a choice a policy
		// should force.
		"NODE_ALGOD_TOKEN",
	}
}

// ZeroSignalComposePolicy is the content policy a ZeroSignal relying party
// enforces on a dstack node's measured compose.
//
// It lives here, in the protocol module, rather than being spelled out in the
// proxy and again in the browser client, because the two would then assert the
// same rules in two places and execute them in none — the shape proto/SPEC.md
// and this package exist to avoid. The per-RELEASE data (which zs-node image
// digests are published) is deliberately NOT here: that list moves on each
// consumer's own cadence, exactly like the trusted OS-image list.
//
// WHAT A CLEAN RESULT FROM *THIS POLICY ALONE* DOES NOT ESTABLISH, because the
// distinction is easy to lose: the package implements the template match over
// docker_compose_file (ExtractComposeSkeleton + TrustedComposeSkeletons +
// TrustedNodeImages), but the per-RELEASE half of it is not here. This policy
// leaves EnforceComposeSkeleton unset and both lists empty, so on its own the
// workload is unchecked — a compose pinning `image: ${SOME_VAR}` holds a stable
// compose_hash over arbitrary code and passes every rule enabled here.
//
// THAT IS A PROPERTY OF THIS FUNCTION, NOT OF THE FLEET. Both shipped
// consumers supply the release lists and set the flag: zs-proxy from its config
// defaults, and the browser client from a bundled constant. The lists live
// there rather than here because they move on each consumer's own release
// cadence, exactly like the trusted OS-image list — so a library caller that
// takes this policy verbatim gets the weaker check, and needs to say so rather
// than inherit the fleet's reputation for it.
//
// A consumer supplying the lists sets the flag in the same change. Setting one
// without the other is a defect the policy check reports
// (ViolationPolicyMisconfigured), because a populated list with the flag off
// consults nothing while looking configured.
func ZeroSignalComposePolicy() ComposePolicy {
	no := false
	return ComposePolicy{
		ManifestVersion: 2,
		Runner:          "docker-compose",

		AllowedEnvNames:    ZeroSignalSecretEnvNames(),
		AllowedEnvSuffixes: []string{"_MNEMONIC"},
		// Explicit, because an empty AllowedEnvNames must never be
		// readable as "no constraint" — see the field's godoc.
		EnforceEnvAllowlist: true,

		PreLaunchScriptDigests: PhalaPreLaunchDigests(),

		// Observed on the 2026-08 tdx.small capture. `kms` is the key
		// provider, `tproxy-net` the gateway — both are the platform's
		// own switches, not the operator's, which is why enumerating
		// them is tractable at all. A dstack release adding a feature
		// refuses nodes using it until this moves; that is the stated
		// cost of checking the field rather than ignoring it, and
		// ignoring it is what let it ride through unread.
		AllowedFeatures: []string{"kms", "tproxy-net"},

		Toggles: ComposeToggles{
			// The one toggle pinned on evidence rather than
			// preference. local_key_provider_enabled means the CVM
			// derives its own keys instead of taking them from
			// Phala's KMS; the deployment this policy describes uses
			// the KMS path, and a node flipping it is a different
			// key-custody story than the one attested.
			LocalKeyProvide: &no,
		},
	}
}

// ACIUpstreamPreLaunchDigests are the pre-launch scripts observed on Phala's
// ACI/1 deployments — the aggregator gateway and the per-model GPU CVMs both
// run the same one.
//
// SEPARATE FROM PhalaPreLaunchDigests ON PURPOSE, even though both lists hold
// Phala-injected scripts. That list is what a ZeroSignal node's own compose may
// carry, and every entry on it was read off a CVM we deployed. This one is what
// a third party's compose may carry. Merging them would let a script blessed
// for an upstream satisfy the check on our own node, which is the
// released-engine-passes-as-released-node confusion in a different costume.
//
// Measured 2026-09-24 on `inference.phala.com` (gateway, repo_commit
// 8d0a666a) and on the `qwen3-8-27b-uncensored.use1.phala.com` model CVM: the
// same 13166-byte script on both. It is in NEITHER entry of
// PhalaPreLaunchDigests, so this list could not have been inherited.
//
// Moves on Phala's schedule, with no version to track — the script is injected
// server-side by the Phala Cloud API, not shipped in their CLI. Expect it to
// move without announcement; that is why it is a list and not a constant.
func ACIUpstreamPreLaunchDigests() []string {
	return []string{
		"bf12939bc82c9bdd103b6b1226913e6da58ed7cfcfc7c7ae808ac0813715b9a8",
	}
}

// ACIUpstreamComposePolicy is the content policy for a third-party ACI/1
// upstream's measured compose — Phala's gateway or one of their per-model GPU
// CVMs. It is NOT a policy for a ZeroSignal node; see ZeroSignalComposePolicy.
//
// Three deliberate differences from our own policy, each because the document
// belongs to someone else:
//
//   - EnforceEnvAllowlist is FALSE. Their env set is theirs, and enumerating
//     it would turn every upstream release into a refusal. The root-backdoor
//     check still runs — that one is about a capability, not a naming
//     convention, and it is the only env rule that survives the handover.
//   - No skeleton or image lists. ExtractComposeSkeleton templates a zs-node
//     compose and its NODE_CONFIG_YAML hole; run against a gateway it reports
//     rules that were never about them.
//   - Its own pre-launch digest set.
//
// allowedBackdoorEnvs is the carve-out and it is a PARAMETER rather than a
// constant, so the concession lives in an operator's config — which on dstack
// is literal text inside the measured compose. A payer reading our own
// app_compose therefore sees exactly which exception we took. Passing nil
// gives the strict policy, which is what a caller that has not decided should
// get.
func ACIUpstreamComposePolicy(allowedBackdoorEnvs []string) ComposePolicy {
	no := false
	return ComposePolicy{
		ManifestVersion: 2,
		Runner:          "docker-compose",

		// See the godoc: their names are theirs. The backdoor check is
		// unconditional and is not switched off by this.
		EnforceEnvAllowlist:     false,
		AllowedRootBackdoorEnvs: allowedBackdoorEnvs,

		// The concession above is honoured only on an image where the
		// channel has no consumer. Defaulted here rather than left to the
		// caller because a caller who passed allowedBackdoorEnvs and left
		// this empty would get a refusal they could not explain — and the
		// safe-image set is not operator-varying the way the concession is.
		RootBackdoorSafeOSImages: OSImagesWithoutSSHDaemon(),

		PreLaunchScriptDigests: ACIUpstreamPreLaunchDigests(),

		// MEASURED, not inherited from ZeroSignalComposePolicy: both
		// documents captured 2026-09-24 — the gateway (repo_commit
		// 8d0a666a) and the qwen3-8-27b-uncensored model CVM — declare
		// exactly these two. That they match our own list is a fact about
		// Phala running both on the same platform, not a shared constant,
		// so a future divergence belongs here rather than in a merge of the
		// two policies.
		AllowedFeatures: []string{"kms", "tproxy-net"},

		Toggles: ComposeToggles{
			// Same reason as ZeroSignalComposePolicy: the attested
			// key-custody story is the KMS one.
			LocalKeyProvide: &no,
		},
	}
}

// ---------------------------------------------------------------------------
// The compose skeleton
// ---------------------------------------------------------------------------

// Placeholders substituted for the three operator-varying spans. They are the
// only text a skeleton contains that the operator's document does not.
const (
	skeletonImagePlaceholder        = "<ZS-IMAGE>"
	skeletonConfigPlaceholder       = "<ZS-CONFIG>"
	skeletonEngineConfigPlaceholder = "<ZS-ENGINE-CONFIG>"
)

// composeConfigKey is the env name whose block scalar carries the node's
// measured configuration — the one span an operator is expected to author.
const composeConfigKey = "NODE_CONFIG_YAML"

// ComposeEngineConfigKey names the compose top-level `configs:` entry whose
// `content:` block scalar carries the inference engine's own configuration.
//
// WHY A SENTINEL NAME AND NOT A BARE `content:`. The compose spec fixes the key
// as `content`, which is far too generic to lift on sight — any future config
// entry would have its body silently excluded from the measurement, and the
// whole safety of this walk is that a span nobody checks can never contain
// compose directives. So the lift requires the EXACT two-line shape
//
//	<indent><ComposeEngineConfigKey>:
//	<deeper>content: |
//
// and the sentinel line itself stays in the skeleton as structure. A `content:`
// anywhere else is ordinary text and is hashed like any other line, which is
// the safe direction: it can only make a document stop matching.
// Exported because operator-facing messages elsewhere have to name the block an
// operator must edit, and a second hand-written copy of that string is one
// rename away from telling them to edit a key that no longer exists.
const ComposeEngineConfigKey = "zs-engine-config"

// Errors from ExtractComposeSkeleton. Each is a refusal, never a fallback:
// a document this cannot take apart is a document no skeleton describes.
var (
	ErrComposeTabIndent = errors.New("attest: docker_compose_file indents with a tab")
	ErrComposeNoImage   = errors.New("attest: docker_compose_file declares no image")
	// ErrComposeUnpinnedSidecar refuses a non-lifted image that is not pinned by
	// digest. The skeleton is the ONLY thing checking a second image — it is
	// never compared against a release list — so an unpinned one would hold a
	// stable skeleton digest over arbitrary bytes. That is the same attack
	// TrustedNodeImages exists to stop for the first image, and the reason the
	// first one is never trusted to the release author's discipline either.
	ErrComposeUnpinnedSidecar = errors.New(
		"attest: docker_compose_file declares a second image that is not pinned by digest")
)

// ExtractComposeSkeleton splits the measured compose text into the parts an
// operator may vary and the structure they may not, returning the structure
// with the varying spans replaced by fixed placeholders, plus the image
// reference it lifted out.
//
// WHY A SKELETON RATHER THAN A YAML PARSE. The rules a verifier wants —
// published image, no host bind mounts, no privileged, ports limited to 9090 —
// all read structure out of a YAML document, and implementing that twice means
// two YAML parsers deciding a security question about the same bytes. Parsers
// disagree (anchors, merge keys, duplicate keys, quoting), and a disagreement
// here is not a crash: it is the proxy and the browser client reaching opposite
// verdicts on identical evidence, silently, which is the exact failure the
// one-implementation-per-language rule exists to prevent.
//
// Comparing the structure against a published release instead inverts the
// problem. Nothing has to enumerate what is forbidden, because everything not
// in the release's own compose is forbidden by construction — a bind mount, a
// `privileged: true`, a second service, an added port, a `command:` override
// are all just text the skeleton does not contain. The cost is rigidity: an
// operator who reformats their compose, or varies anything outside the two
// holes, no longer matches. That is deliberate. Under this design the compose
// is a published artifact with the operator's config written into it, not a
// file they compose themselves.
//
// The two holes:
//
//   - the FIRST image REFERENCE, because the digest moves per release; the
//     caller checks it against a release list rather than baking it into the
//     skeleton.
//   - the `NODE_CONFIG_YAML` block scalar, which is the operator's whole
//     configuration. NOTHING HERE CHECKS IT, and no verifier parses it: the
//     text is not what the node runs, since env overrides and dstack's
//     `${VAR}` substitution both apply after the compose is hashed. What a
//     payer relies on from it — where plaintext goes — reaches the verifier
//     as the posture the measured binary derived from its effective config,
//     bound into report_data by HPosture.
//
// A SECOND `image:` IS NOT LIFTED — it stays in the skeleton as literal text,
// and it MUST be pinned by digest (ErrComposeUnpinnedSidecar). That combination
// is a stronger pin than lifting it, not a weaker one; either half alone is a
// hole. Literal-but-unpinned would hold one stable skeleton digest over any
// bytes the operator later supplies through `${VAR}` — dstack hashes this
// document before expansion — which is exactly the attack TrustedNodeImages
// stops for the first image. Pinned-but-lifted is the next paragraph. The
// sealed_local rung runs an inference engine as that sidecar, so the document
// has two images and this used to refuse it outright. Lifting the engine too would
// mean two references checked against one flat TrustedNodeImages list, where a
// released ENGINE image would pass as a released NODE image — the confusion a
// flat list invites. Leaving it literal means the release's own engine digest is
// part of the structure an operator may not vary: bump the engine and it is a
// node release, which is the correct coupling for something that sees plaintext
// prompts.
//
// "First" is well-defined here for the same reason the rest of the design works:
// the skeleton is compared byte-for-byte against a published digest, so
// reordering the services, swapping the engine digest, or adding a third one all
// change the skeleton and stop matching. An attacker who puts their own image
// first has it lifted and checked against the release list, which refuses it.
// Nothing rests on guessing which service is the node's.
//
// The block-scalar walk is the only subtle part, and it follows YAML's own
// rule: the scalar runs to the first following line that is neither blank nor
// indented deeper than the key. Consuming too FEW lines is safe — the leftovers
// stay in the skeleton and it stops matching. Consuming too MANY would be a
// hole, because real compose directives would be swallowed into the span
// nobody checks, so the walk must never be loosened past that rule.
//
// A tab anywhere in a line's leading whitespace is refused outright: YAML
// forbids tab indentation, so its presence means the document is not what the
// operator thinks it is, and it makes "indented deeper" ambiguous — exactly the
// ambiguity the paragraph above says must not exist.
func ExtractComposeSkeleton(dockerCompose string) (skeleton, imageRef string, err error) {
	s, ref, _, err := ExtractComposeSpans(dockerCompose)
	return s, ref, err
}

// ExtractComposeSpans is ExtractComposeSkeleton plus the engine-config bodies it
// lifted, in document order.
//
// THE BODIES ARE RETURNED RATHER THAN RE-FOUND, and that is a security property,
// not an optimization. The content rule (EngineConfigViolations) has to scan
// exactly the text the skeleton stopped covering. When it walked the document
// itself instead, the two walks disagreed in three separate ways, each of which
// let a forbidden key ride in a span nothing checked:
//
//   - This walk SKIPS the NODE_CONFIG_YAML body, which the operator authors
//     freely and which is itself lifted. A second walk did not, so a decoy
//     `zs-engine-config:` planted in that body captured the scan and it never
//     reached the real span — while the skeleton digest stayed byte-identical to
//     the honest release. Full enforcement caught nothing.
//   - This walk lifts EVERY engine span; a scan that stopped at the first left
//     the rest unread.
//   - This walk REFUSES a malformed document; a scan that returned "absent"
//     instead reported no violations for it.
//
// Returning the spans makes all three unrepresentable: there is one walk, so
// there is nothing for a second one to disagree with.
func ExtractComposeSpans(dockerCompose string) (skeleton, imageRef string, engineBodies []string, err error) {
	lines := strings.Split(dockerCompose, "\n")
	out := make([]string, 0, len(lines))

	// Armed by the `zs-engine-config:` sentinel and disarmed by the very next
	// non-blank line, whatever it is. The narrow window is the safety property:
	// a `content:` that is not the one directly under the sentinel is never
	// lifted, so the generic key cannot swallow a span nobody checks.
	engineArmed := false
	engineSentinelIndent := 0

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		indent := leadingSpace(line)
		if strings.ContainsRune(indent, '\t') {
			return "", "", nil, fmt.Errorf("%w (line %d)", ErrComposeTabIndent, i+1)
		}

		if engineArmed {
			if trimASCII(line) == "" {
				out = append(out, line)
				continue
			}
			if depth, ok := composeEngineConfigBlockStart(line, engineSentinelIndent); ok {
				engineArmed = false
				out = append(out, strings.TrimRight(line, " ")+"\n"+skeletonEngineConfigPlaceholder)
				end, err := consumeBlockScalar(lines, i, depth)
				if err != nil {
					return "", "", nil, err
				}
				// EVERY span is collected, not just the first. The walk lifts
				// them all, so a scan reading only one would leave the rest
				// outside both the measurement and the content rule.
				if end > i {
					engineBodies = append(engineBodies, strings.Join(lines[i+1:end+1], "\n"))
				}
				i = end
				continue
			}
			engineArmed = false
		}

		// ONLY THE FIRST image is lifted; every later one stays in the
		// skeleton as literal text. See the "second image" paragraph in the
		// godoc for why that is a pin rather than a gap.
		if ref, ok := composeImageRef(line); ok {
			if imageRef == "" {
				imageRef = ref
				out = append(out, indent+"image: "+skeletonImagePlaceholder)
				continue
			}
			// A later image is checked against no release list, so its literal
			// bytes are the whole pin — and a `${VAR}` or a tag is not a pin.
			// dstack hashes this document BEFORE expanding `${VAR}`, so a
			// release written that way would publish one skeleton digest under
			// which the operator runs any engine they like, in the process that
			// sees plaintext prompts.
			if !isDigestPinnedRef(ref) {
				return "", "", nil, fmt.Errorf("%w: %q (line %d)", ErrComposeUnpinnedSidecar, ref, i+1)
			}
			out = append(out, line)
			continue
		}

		if depth, ok := composeConfigBlockStart(line); ok {
			out = append(out, strings.TrimRight(line, " ")+"\n"+skeletonConfigPlaceholder)
			end, err := consumeBlockScalar(lines, i, depth)
			if err != nil {
				return "", "", nil, err
			}
			// The body is SKIPPED, and that is exactly why the content rule
			// must read this function's output rather than re-walking. A
			// sentinel planted in here is invisible to the lift, so a second
			// walk that saw it would scan a decoy and never reach the real
			// span — with the skeleton digest unmoved, because this body is
			// lifted too.
			i = end
			continue
		}

		if d, ok := composeEngineConfigSentinel(line); ok {
			engineArmed = true
			engineSentinelIndent = d
		}

		out = append(out, line)
	}

	if imageRef == "" {
		return "", "", nil, ErrComposeNoImage
	}
	return strings.Join(out, "\n"), imageRef, engineBodies, nil
}

// ComposeSkeletonDigest is the value a release list holds: sha256 of the
// skeleton, lowercase hex.
func ComposeSkeletonDigest(skeleton string) string {
	sum := sha256.Sum256([]byte(skeleton))
	return hex.EncodeToString(sum[:])
}

// asciiSpace is the ONLY whitespace class anything in this file trims, and
// naming it is the point — `strings.TrimSpace` must not appear here.
//
// Go's TrimSpace uses unicode.IsSpace; JavaScript's String.prototype.trim uses
// its own WhiteSpace ∪ LineTerminator set. The two DISAGREE, in both
// directions: U+0085 (NEL) is space to Go and not to JS, U+FEFF (BOM) is space
// to JS and not to Go. Borrowing each language's notion therefore builds a
// verdict split into a byte-exact security gate — measured, not theorized. With
// a `docker_compose_file` of exactly one U+0085 Go reported
// empty_docker_compose and TS accepted the document; with one U+FEFF the two
// swapped. The same split moved the skeleton digest and flipped the
// image-reference match. (Named by codepoint, never written literally — either
// character in this file's own bytes is at best noise and, for U+FEFF, a
// compile error.)
//
// That matters most where it is cheapest to overlook: empty_docker_compose is
// the ONLY rule guarding docker_compose_file for a consumer that ships
// EnforceComposeSkeleton false, and a vacuous compose is the shape this package
// exists to refuse. (Both shipped consumers now set the flag and supply the
// release lists — see ZeroSignalComposePolicy — but the flag is public API and
// off is a reachable configuration, which is what this rule has to survive.)
//
// So the class is written out. It is deliberately ASCII-only — YAML's own
// "empty line" is spaces and tabs, the walk already refuses tabs in
// indentation, and every value compared here (a hex digest, an env name, an
// image reference) is ASCII by construction. Anything exotic is then content,
// which is the fail-CLOSED direction: it survives the trim, fails to match, and
// is refused rather than silently accepted.
const asciiSpace = " \t\n\v\f\r"

// trimASCII is TrimSpace over asciiSpace. Mirrors `trimAscii` in
// ts/src/attest/compose.ts byte for byte; change neither alone.
func trimASCII(s string) string { return strings.Trim(s, asciiSpace) }

// blankSpace is the UNION of Go's unicode.IsSpace and JavaScript's trim set,
// plus the two codepoints where they disagree. It exists for exactly one
// question — "does this compose contain nothing at all?" — and it is
// deliberately the opposite extreme from asciiSpace above.
//
// The two predicates point in opposite directions because fail-closed means
// opposite things for them. Normalizing a VALUE (an env name, a hex digest, an
// image reference) must trim as LITTLE as possible: anything exotic left in
// place fails to match its allowlist and the node is refused. Deciding a
// document is VACUOUS must trim as MUCH as possible: every character that
// could be nothing must count as nothing, or the rule is sidesteppable.
//
// And it was. With only the ASCII class, a docker_compose_file of one U+0085
// verified CLEAN in both languages — agreeing, which was the bug fixed first,
// but agreeing on the wrong answer. empty_docker_compose is the only rule
// guarding docker_compose_file for a consumer shipping EnforceComposeSkeleton
// false, so one invisible character disabled it. The vectors caught that; no
// hand-written test would have, because the fixture nobody thinks to write is
// the one made of characters nobody can see.
var blankSpace = []rune{
	' ', '\t', '\n', '\v', '\f', '\r',
	0x0085, // NEL — space to Go, not to JS
	0x00A0, // NBSP
	0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005,
	0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
	0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
	0xFEFF, // BOM — space to JS, not to Go
}

// isBlank reports whether s consists only of characters that could be nothing.
// Mirrors `isBlank` in ts/src/attest/compose.ts; change neither alone.
func isBlank(s string) bool {
	for _, r := range s {
		blank := false
		for _, b := range blankSpace {
			if r == b {
				blank = true
				break
			}
		}
		if !blank {
			return false
		}
	}
	return true
}

// leadingSpace returns a line's indentation verbatim, tabs included, so the
// caller can refuse them rather than silently measuring them as one column.
func leadingSpace(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
}

// isDigestPinnedRef reports whether ref names immutable bytes:
// `<repository>@sha256:<64 lowercase hex>`.
//
// Hand-rolled rather than a regexp for the same reason nothing in this file
// parses YAML — one rule, spelled identically in Go and TS, with no engine
// between the two that could disagree about it. Lowercase-only is deliberate:
// the digest a registry serves is lowercase, and accepting both cases would let
// two spellings of one reference produce two skeletons.
//
// `${` ANYWHERE IN THE REFERENCE IS REFUSED, including in the repository half.
// dstack hashes docker_compose_file BEFORE expanding `${VAR}`, so an
// interpolated reference is not a value this document pins — it is a value the
// operator supplies afterwards, out of the measurement. The digest half being
// literal would still content-address the bytes, so an interpolated repository
// is not by itself an escape; it is refused because the rule this function
// exists to enforce is spelled `<repository>@sha256:<hex>` in SPEC §5, no
// registry accepts `${` in a repository name, and a check that admitted it
// would make three documents' worth of "a `${VAR}` is not a pin" false.
func isDigestPinnedRef(ref string) bool {
	if strings.Contains(ref, "${") {
		return false
	}
	repo, digest, ok := strings.Cut(ref, "@sha256:")
	if !ok || repo == "" || len(digest) != 64 {
		return false
	}
	for i := 0; i < len(digest); i++ {
		c := digest[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// composeImageRef matches a bare `image: <ref>` line.
//
// Deliberately strict about shape — no quotes, no trailing comment. Anything
// else fails to match, so the line stays literal in the skeleton and the digest
// comparison refuses it. That is the right outcome: the operator is expected to
// have copied a published compose, and a reformatted one is not it.
func composeImageRef(line string) (string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimLeft(line, " "), "image:")
	if !ok {
		return "", false
	}
	ref := trimASCII(rest)
	if ref == "" || strings.ContainsAny(ref, " \t#") {
		return "", false
	}
	return ref, true
}

// composeConfigBlockStart matches `NODE_CONFIG_YAML: |` (with any block-scalar
// chomping indicator) and returns the key's indentation depth.
func composeConfigBlockStart(line string) (int, bool) {
	return blockScalarStart(line, composeConfigKey)
}

// composeEngineConfigSentinel matches the bare `zs-engine-config:` key line
// that must immediately precede the engine config's `content:` block, and
// returns its indentation depth.
//
// The key must have NOTHING after the colon: a value on the same line is not
// the shape this lifts, and treating it as one would arm the lift on a document
// whose next `content:` belongs to something else entirely.
func composeEngineConfigSentinel(line string) (int, bool) {
	trimmed := strings.TrimLeft(line, " ")
	rest, ok := strings.CutPrefix(trimmed, ComposeEngineConfigKey+":")
	if !ok || trimASCII(rest) != "" {
		return 0, false
	}
	return len(line) - len(trimmed), true
}

// composeEngineConfigBlockStart matches the `content: |` line carrying the
// engine configuration, given the indent of the sentinel that armed it. The
// content key must be indented DEEPER than the sentinel, or it is not inside
// that entry at all.
func composeEngineConfigBlockStart(line string, sentinelIndent int) (int, bool) {
	depth, ok := blockScalarStart(line, "content")
	if !ok || depth <= sentinelIndent {
		return 0, false
	}
	return depth, true
}

// consumeBlockScalar returns the index of the LAST line belonging to the block
// scalar whose key sits at line index start with indentation depth.
//
// Blank lines belong to the scalar regardless of their own indentation — YAML's
// rule, and treating a blank line as a terminator would end the span early on
// any config with a paragraph break in it. Consuming too FEW lines is safe (the
// leftovers stay in the skeleton and it stops matching); consuming too MANY is a
// hole, because real compose directives would land in a span nobody checks.
//
// Shared by both lifted scalars for that reason: two copies of this walk are two
// chances to get the "too many" direction wrong, and only one of them would be
// covered by whichever test someone remembered to write.
func consumeBlockScalar(lines []string, start, depth int) (int, error) {
	i := start
	for i+1 < len(lines) {
		next := lines[i+1]
		if trimASCII(next) == "" {
			i++
			continue
		}
		ni := leadingSpace(next)
		if strings.ContainsRune(ni, '\t') {
			return 0, fmt.Errorf("%w (line %d)", ErrComposeTabIndent, i+2)
		}
		if len(ni) <= depth {
			break
		}
		i++
	}
	return i, nil
}

// blockScalarStart matches `<key>: |` (with any block-scalar chomping
// indicator) and returns the key's indentation depth. Shared so the two lifted
// scalars cannot drift on which indicators they accept — a document one of them
// took apart and the other did not would produce two skeletons for one file.
func blockScalarStart(line, key string) (int, bool) {
	trimmed := strings.TrimLeft(line, " ")
	rest, ok := strings.CutPrefix(trimmed, key+":")
	if !ok {
		return 0, false
	}
	switch trimASCII(rest) {
	case "|", "|-", "|+", ">", ">-", ">+":
		return len(line) - len(trimmed), true
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// VerifyAppCompose checks a published app-compose document against the
// measurement that was actually replayed out of the event log, then against the
// content policy.
//
// ORDER IS THE SAFETY PROPERTY. The hash gate runs first and returns before a
// single field is read, so every rule below it is a statement about the
// document the hardware measured rather than about a document the node chose to
// send. measurements must come from VerifyEventLog — that is, from a replay
// already checked against the quote — and never from a self-reported field.
//
// raw must be the app_compose string EXACTLY as received. Re-marshalling it
// first would reorder keys and change whitespace, and the digest would then be
// over a document dstack never saw.
// A policy carrying AllowedRootBackdoorEnvs is REFUSED here rather than
// honoured. This entry point is the one every ZeroSignal-node verifier uses,
// and a root-shell exemption is never correct for our own node; refusing it is
// what stops the exemption reaching a caller that has nowhere to report it.
// Appraising a third party's compose goes through VerifyUpstreamAppCompose.
func VerifyAppCompose(raw string, measurements map[string]string, policy ComposePolicy) (*AppCompose, error) {
	if len(policy.AllowedRootBackdoorEnvs) > 0 {
		return nil, &ComposePolicyError{Violations: []Violation{{
			Code: ViolationPolicyMisconfigured,
			Detail: fmt.Sprintf(
				"this policy exempts %d root-backdoor env name(s), which VerifyAppCompose "+
					"never honours — use VerifyUpstreamAppCompose, which returns the exemptions",
				len(policy.AllowedRootBackdoorEnvs)),
		}}}
	}
	doc, _, err := verifyAppCompose(raw, measurements, policy)
	return doc, err
}

// VerifyUpstreamAppCompose is VerifyAppCompose for a document that is not
// ours: a third-party attested upstream whose compose we appraise but do not
// author.
//
// It differs in exactly one way — it honours ComposePolicy.AllowedRootBackdoorEnvs
// — and it returns the resulting exemptions as a value the caller must receive.
// That signature is the point. An exemption that stops at the verifier is
// indistinguishable from a clean appraisal by the time it reaches a payer, and
// this tier's whole premise is "checkable rather than promised".
//
// Exemptions accompany a nil error on the success path, and a caller that
// ignores them publishes a stronger claim than it verified. They also come back
// ALONGSIDE a ComposePolicyError, because a document can concede one rule and
// fail another — the two answers are about different rules, so the exemption
// slice is not a "no violations" signal and a `len(ex) > 0` check is never a
// stand-in for `err == nil`. Callers that publish carve-outs must gate on the
// error and read the slice, in that order.
func VerifyUpstreamAppCompose(raw string, measurements map[string]string, policy ComposePolicy) (*AppCompose, []Exemption, error) {
	return verifyAppCompose(raw, measurements, policy)
}

func verifyAppCompose(raw string, measurements map[string]string, policy ComposePolicy) (*AppCompose, []Exemption, error) {
	if err := VerifyComposeHash(raw, measurements); err != nil {
		return nil, nil, err
	}

	doc, unknown, err := parseAppCompose(raw)
	if err != nil {
		return nil, nil, err
	}

	// A root-backdoor concession is honoured only on a guest image where the
	// channel has no consumer. Gating it HERE rather than inside check() is
	// deliberate: check() takes the document and the policy, and giving it the
	// measurements too would let any later rule reach for them, which is how
	// a content policy starts silently depending on the replay. This is the one
	// rule whose justification is a property of the image, so this is the one
	// place that reads the image.
	//
	// The direction is fail-closed: an os-image-hash that is absent, or present
	// but not named in RootBackdoorSafeOSImages, drops the concession and the
	// strict rule fires. A caller that sets AllowedRootBackdoorEnvs and forgets
	// RootBackdoorSafeOSImages therefore gets a refusal, not a carve-out.
	if len(policy.AllowedRootBackdoorEnvs) > 0 {
		osImage := normalizeHex(measurements[EventOSImageHash])
		if osImage == "" || !containsFold(policy.RootBackdoorSafeOSImages, osImage) {
			policy.rootBackdoorWithheld = policy.AllowedRootBackdoorEnvs
			policy.AllowedRootBackdoorEnvs = nil
			policy.rootBackdoorWithheldOn = osImage
			if osImage == "" {
				policy.rootBackdoorWithheldOn = "(absent)"
			}
		}
	}

	v, ex := policy.check(doc, unknown)
	if len(v) > 0 {
		return doc, ex, &ComposePolicyError{Violations: v}
	}
	return doc, ex, nil
}

// VerifyComposeHash is the gate on its own: does this document hash to the
// value the event-log replay recovered?
//
// Exported separately because it is the ONLY step that establishes provenance,
// and a caller may legitimately want it without any content policy — a node
// checking its own evidence at mint time, say. Everything in ComposePolicy is a
// statement about a document; this is the step that makes it a statement about
// THIS CVM.
//
// measurements must come from VerifyEventLog. Passing a self-reported map turns
// the whole package into an elaborate way of comparing a document to itself.
func VerifyComposeHash(raw string, measurements map[string]string) error {
	want := normalizeHex(measurements[EventComposeHash])
	if want == "" {
		return ErrNoComposeHash
	}
	if raw == "" {
		return ErrNoAppCompose
	}
	sum := sha256.Sum256([]byte(raw))
	got := hex.EncodeToString(sum[:])
	if got != want {
		return fmt.Errorf("%w (document hashes to %s, log measured %s)",
			ErrComposeHashMismatch, got, want)
	}
	return nil
}

// parseAppCompose decodes the document and reports any top-level key this
// package does not model.
func parseAppCompose(raw string) (*AppCompose, []string, error) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrAppComposeMalformed, err)
	}
	// `null` is valid JSON and unmarshals into a nil map without error,
	// which then walks the whole policy against a ZERO document — a pile of
	// violations describing fields nobody sent, where TS raised
	// app_compose_malformed. Both end in a refusal, so no node's verdict
	// changed; what differed was WHICH finding an operator was shown, and a
	// cross-language disagreement in the parse layer of a security gate is
	// the thing this module's whole mirror discipline exists to prevent.
	// Caught by the golden vectors on their first run.
	if keys == nil {
		return nil, nil, fmt.Errorf("%w: not a JSON object", ErrAppComposeMalformed)
	}
	var unknown []string
	for k := range keys {
		if !knownAppComposeFields[k] {
			unknown = append(unknown, k)
		}
	}
	sort.Strings(unknown)

	var doc AppCompose
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrAppComposeMalformed, err)
	}
	return &doc, unknown, nil
}

func (p ComposePolicy) check(c *AppCompose, unknown []string) ([]Violation, []Exemption) {
	var v []Violation
	var ex []Exemption
	add := func(code ViolationCode, format string, args ...any) {
		v = append(v, Violation{Code: code, Detail: fmt.Sprintf(format, args...)})
	}
	// subject is separate from the format args because it is the machine-read
	// half — see Exemption.WireTag.
	exempt := func(code ViolationCode, subject, format string, args ...any) {
		ex = append(ex, Exemption{
			Code:    code,
			Detail:  fmt.Sprintf(format, args...),
			Subject: subject,
		})
	}

	for _, k := range unknown {
		add(ViolationUnknownField, "this dstack release carries a top-level field %q that no rule here covers", k)
	}
	if p.ManifestVersion != 0 && c.ManifestVersion != p.ManifestVersion {
		add(ViolationManifestVersion, "want %d, got %d", p.ManifestVersion, c.ManifestVersion)
	}
	if p.Runner != "" && c.Runner != p.Runner {
		add(ViolationRunner, "want %q, got %q", p.Runner, c.Runner)
	}

	// The verifier's own configuration, checked before the node's document,
	// because a policy carrying reference data it never consults is not a
	// lenient policy — it is a broken one, and it looks identical to a
	// deliberate rollout state.
	if !p.EnforceComposeSkeleton &&
		(len(p.TrustedComposeSkeletons) > 0 || len(p.TrustedNodeImages) > 0) {
		add(ViolationPolicyMisconfigured,
			"this policy carries %d trusted skeleton(s) and %d trusted image(s) but "+
				"EnforceComposeSkeleton is false, so neither list is consulted",
			len(p.TrustedComposeSkeletons), len(p.TrustedNodeImages))
	}

	// Deliberately NOT gated on EnforceComposeSkeleton. That flag chooses
	// whether the document is matched against a published release; this is a
	// statement about the document's own content, and it must hold for a node
	// pinned by whole-document hash just as much as for a released one.
	for _, key := range EngineConfigViolations(c.DockerCompose) {
		add(ViolationEngineConfigKey,
			"the engine config declares %q, which changes what the model produces "+
				"rather than how fast it produces it — the weights digest cannot see it",
			key)
	}

	if isBlank(c.DockerCompose) {
		add(ViolationEmptyDockerCompose, "the measured document declares no compose at all")
	} else if p.EnforceComposeSkeleton {
		skeleton, imageRef, serr := ExtractComposeSkeleton(c.DockerCompose)
		switch {
		case serr != nil:
			// A document that cannot be taken apart is a document no
			// skeleton describes, so this is a violation and never a
			// skip — the shape that would otherwise let an operator
			// disable the check by writing a compose we cannot parse.
			// The sentinel's own "attest: " prefix is stripped so the
			// detail reads the same in both languages — TS raises a
			// ComposeSkeletonError whose message carries no such
			// prefix. Codes are the stable contract and details are
			// prose, but a UI diffing the two across implementations
			// should not see a difference that means nothing.
			add(ViolationComposeSkeleton, "cannot be read as a release compose: %s",
				strings.TrimPrefix(serr.Error(), "attest: "))
		default:
			if !containsFold(p.TrustedComposeSkeletons, ComposeSkeletonDigest(skeleton)) {
				add(ViolationComposeSkeleton,
					"does not match any published release compose (skeleton sha256 %s)",
					ComposeSkeletonDigest(skeleton))
			}
			// Checked separately from the skeleton because it moves on
			// a different cadence: the skeleton changes when the
			// deployment's SHAPE changes, the image on every release.
			if !containsExact(p.TrustedNodeImages, imageRef) {
				add(ViolationNodeImage,
					"runs %s, which is not a published zs-node release", imageRef)
			}
		}
	}

	backdoor := make(map[string]bool, len(RootBackdoorEnvs()))
	for _, n := range RootBackdoorEnvs() {
		backdoor[strings.ToUpper(n)] = true
	}
	// Only names that ARE backdoor names can be exempted. A policy naming
	// something else here would otherwise read as having conceded a rule it
	// never reached, and the exemption list is meant to be the honest
	// account of what was conceded.
	exemptBackdoor := make(map[string]bool, len(p.AllowedRootBackdoorEnvs))
	for _, n := range p.AllowedRootBackdoorEnvs {
		up := strings.ToUpper(trimASCII(n))
		if backdoor[up] {
			exemptBackdoor[up] = true
		}
	}
	// Names a concession covered before the image gate dropped it. Same
	// canonicalization and same backdoor filter as above, so a policy listing
	// a non-backdoor name earns no sharper message than it earns a carve-out.
	withheld := make(map[string]bool, len(p.rootBackdoorWithheld))
	for _, n := range p.rootBackdoorWithheld {
		up := strings.ToUpper(trimASCII(n))
		if backdoor[up] {
			withheld[up] = true
		}
	}
	allowed := make(map[string]bool, len(p.AllowedEnvNames))
	for _, n := range p.AllowedEnvNames {
		allowed[strings.ToUpper(trimASCII(n))] = true
	}
	for _, name := range c.AllowedEnvs {
		up := strings.ToUpper(trimASCII(name))
		switch {
		case backdoor[up] && exemptBackdoor[up]:
			// Subject is the CANONICAL (trimmed, upper) name, not the
			// document's spelling: it is compared against a verifier's own
			// expectation, and dstack env names are uppercase by convention
			// rather than by rule, so a stray ` dstack_root_password` in a
			// compose must not publish a carve-out nothing matches.
			exempt(ViolationRootBackdoorEnv, up,
				"%s installs an operator-held root credential inside the CVM; "+
					"this policy exempts it, so a clean result here does not mean "+
					"the measurement pins what runs", name)
		case backdoor[up] && withheld[up]:
			// The operator DID concede this name. Say so, and say what
			// withheld it, or the refusal is indistinguishable from the one
			// they get for conceding nothing.
			add(ViolationRootBackdoorEnv,
				"%s installs an operator-held root credential inside the CVM; "+
					"this policy exempts it, but the concession was withheld "+
					"because guest image %s has not been enumerated for an SSH "+
					"daemon (see OSImagesWithoutSSHDaemon)", name, p.rootBackdoorWithheldOn)
		case backdoor[up]:
			add(ViolationRootBackdoorEnv,
				"%s installs an operator-held root credential inside the CVM", name)
		case p.EnforceEnvAllowlist && !allowed[up] && !hasAllowedSuffix(p.AllowedEnvSuffixes, up):
			add(ViolationEnvNotAllowed,
				"%s is not a name this policy permits in the unmeasured env channel", name)
		}
	}

	if c.PreLaunchScript != "" {
		sum := sha256.Sum256([]byte(c.PreLaunchScript))
		got := hex.EncodeToString(sum[:])
		if !containsFold(p.PreLaunchScriptDigests, got) {
			add(ViolationPreLaunchScript,
				"runs an unrecognized root boot hook (%d bytes, sha256 %s)",
				len(c.PreLaunchScript), got)
		}
	}

	// features and storage_fs were modelled and never read, which is the
	// worst of both: listing them in knownAppComposeFields suppressed the
	// unknown_field report that would have surfaced them, so a dstack
	// feature switch or a different encrypted-FS backend rode through
	// reporting clean. They are values, not merely names.
	if len(p.AllowedFeatures) > 0 {
		for _, f := range c.Features {
			if !containsFold(p.AllowedFeatures, trimASCII(f)) {
				add(ViolationFeature,
					"declares the dstack feature %q, which this policy does not permit", f)
			}
		}
	}
	if p.StorageFS != "" && !strings.EqualFold(trimASCII(c.StorageFS), p.StorageFS) {
		add(ViolationStorageFS, "uses the %q storage backend, want %q", c.StorageFS, p.StorageFS)
	}

	for _, t := range []struct {
		name string
		want *bool
		got  bool
	}{
		{"gateway_enabled", p.Toggles.GatewayEnabled, c.GatewayEnabled},
		{"tproxy_enabled", p.Toggles.TProxyEnabled, c.TProxyEnabled},
		{"kms_enabled", p.Toggles.KMSEnabled, c.KMSEnabled},
		{"local_key_provider_enabled", p.Toggles.LocalKeyProvide, c.LocalKeyProvide},
		{"no_instance_id", p.Toggles.NoInstanceID, c.NoInstanceID},
		{"secure_time", p.Toggles.SecureTime, c.SecureTime},
		{"public_logs", p.Toggles.PublicLogs, c.PublicLogs},
		{"public_sysinfo", p.Toggles.PublicSysinfo, c.PublicSysinfo},
		{"public_tcbinfo", p.Toggles.PublicTCBInfo, c.PublicTCBInfo},
	} {
		if t.want != nil && *t.want != t.got {
			add(ViolationToggle, "%s: want %t, got %t", t.name, *t.want, t.got)
		}
	}
	return v, ex
}

// normalizeHex lowercases, trims, and strips an 0x prefix. An empty result is
// never a match — the property that makes an empty allowlist fail closed.
func normalizeHex(s string) string {
	return strings.TrimPrefix(strings.ToLower(trimASCII(s)), "0x")
}

// hasAllowedSuffix reports whether an already-uppercased env NAME ends in one
// of the policy's permitted suffixes.
//
// The two guards are the whole safety of it and neither is defensive
// programming: an empty suffix makes strings.HasSuffix true for every name, and
// a suffix not anchored on "_" matches any name merely ending in those letters
// (a bare "MNEMONIC" would admit "NODE_TEE_DATAFLOW_MNEMONIC"-style names, but
// worse, a suffix like "KEY" would admit half the config surface). Skipping a
// malformed entry rather than honouring it keeps a typo from widening the
// policy silently.
func hasAllowedSuffix(suffixes []string, upperName string) bool {
	for _, s := range suffixes {
		up := strings.ToUpper(trimASCII(s))
		if up == "" || !strings.HasPrefix(up, "_") {
			continue
		}
		if strings.HasSuffix(upperName, up) {
			return true
		}
	}
	return false
}

// containsExact is containsFold's case-SENSITIVE twin, for values where case
// is meaningful. An image reference is one: registry paths and tags are
// case-sensitive, so folding them would accept a reference Docker would
// resolve differently — or not at all.
//
// Keeps containsFold's empty-want rule, which is what makes an empty list fail
// closed rather than matching a document that declared nothing.
func containsExact(list []string, want string) bool {
	if trimASCII(want) == "" {
		return false
	}
	for _, v := range list {
		if trimASCII(v) == want {
			return true
		}
	}
	return false
}

func containsFold(list []string, want string) bool {
	if want == "" {
		return false
	}
	for _, v := range list {
		if normalizeHex(v) == want {
			return true
		}
	}
	return false
}
