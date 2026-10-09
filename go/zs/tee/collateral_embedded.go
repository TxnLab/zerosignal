/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tee

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TxnLab/zerosignal/go/attest"
	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/google/go-tdx-guest/pcs"
)

// Serving a node's own carried collateral, as the LAST resort.
//
// SPEC §3e's precedence is PCS -> our own stale cache -> the node's copy,
// and this file is only the third rung. The ordering is not a preference:
// Intel's signature makes a document's CONTENTS unforgeable and says
// nothing about WHICH validly-signed vintage the party under attestation
// chose to hand over, so preferring the carried set would make the node
// the supplier of the criteria it is judged by. attest's
// EmbeddedCollateralMaxAge bounds that; the ordering is what keeps this
// path rare.
//
// WHY THIS IS SHAPED AS A FAKE PCS RATHER THAN AS A VALUE.
// go-tdx-guest's verify.Options has no field for collateral values —
// obtainCollateral is unexported and the only seam is `Getter
// trust.HTTPSGetter`, keyed by URL — so injecting a set means answering
// as Intel. The URL knowledge is therefore go-tdx-guest's, not Intel's
// protocol, and it stays here rather than in proto: that module has no
// go-tdx-guest dependency today and adding one would push it onto node
// and tui, neither of which verifies a quote. proto answers in values
// (attest.CollateralResponses); this file keys them.

// embeddedIssuerChainHeader is the response header each artifact's issuer
// chain rides in.
//
// EXACT, CANONICAL-MIME SPELLINGS, because go-tdx-guest indexes the
// header map directly rather than going through textproto — a
// differently-cased key reads as an absent chain. Note the QE identity
// one especially: it is "Enclave-Identity", not "Qe-Identity", which does
// not match the library's own variable name for it.
var embeddedIssuerChainHeader = map[attest.CollateralArtifact]string{
	attest.CollateralTCBInfo:    "Tcb-Info-Issuer-Chain",
	attest.CollateralQEIdentity: "Sgx-Enclave-Identity-Issuer-Chain",
	attest.CollateralPCKCRL:     "Sgx-Pck-Crl-Issuer-Chain",
}

// ErrNoUsableCarriedCollateral means the node's evidence bundle carries
// no collateral this proxy is willing to fall back to.
var ErrNoUsableCarriedCollateral = errors.New("attestation: no usable node-carried collateral")

// embeddedGetter answers the four PCS requests a verification makes, from
// a set the node carried, and refuses everything else.
//
// REFUSING THE UNKNOWN URL IS THE POINT, not tidiness. A verification
// that asked for an artifact this set does not cover would otherwise fall
// through to a zero-value response, which the library reads as a
// malformed document rather than as a missing one — the failure would
// surface as "this node's evidence is bad" instead of "we could not serve
// it".
type embeddedGetter struct {
	byURL map[string]embeddedAnswer
}

// embeddedAnswer is one artifact plus the header name its issuer chain
// must ride in. Paired here rather than derived at serve time so exactly
// ONE chain header goes out per response: the library indexes a single
// key, so emitting all three would be inert today and would hand it a
// chain for a document it is not reading the moment that changes.
type embeddedAnswer struct {
	header   string
	response attest.CollateralResponse
}

// newEmbeddedGetter builds the URL-keyed answers for one quote.
//
// The set is checked for completeness and freshness BEFORE any of this,
// by the caller — see VerifyTDXQuoteChainCarried.
func newEmbeddedGetter(quote []byte, c *inject.TEECollateral) (*embeddedGetter, error) {
	fmspc, ca, err := attest.PCKPlatformID(quote)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoUsableCarriedCollateral, err)
	}
	responses, err := attest.CollateralResponses(c)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoUsableCarriedCollateral, err)
	}

	byURL := map[string]embeddedAnswer{
		pcs.QeIdentityURL(): {
			header:   embeddedIssuerChainHeader[attest.CollateralQEIdentity],
			response: responses[attest.CollateralQEIdentity],
		},
		pcs.PckCrlURL(ca): {
			header:   embeddedIssuerChainHeader[attest.CollateralPCKCRL],
			response: responses[attest.CollateralPCKCRL],
		},
	}

	// THE fmspc CASING DIFFERS ON THE TWO SIDES OF THIS MAP, and a
	// lookup is an exact string compare. attest.PCKPlatformID returns
	// the UPPER-case hex Intel documents and publishes in the tcbInfo
	// document itself, while go-tdx-guest builds its request from its
	// own hex.EncodeToString of the same extension, which is LOWER-case
	// (pcs.extractAsn1OctetStringExtension). Intel's API is
	// case-insensitive on the query parameter so a real fetch works
	// either way, and the mismatch would surface here only as an
	// unanswered URL reported as "Intel PCS unreachable" — the exact
	// silent failure this path exists to avoid.
	//
	// Registering both is deliberate over normalizing the URL: which
	// parts of a URL are case-insensitive is not ours to decide, and a
	// normalizer would have to encode that guess.
	for _, f := range []string{strings.ToUpper(fmspc), strings.ToLower(fmspc)} {
		byURL[pcs.TcbInfoURL(f)] = embeddedAnswer{
			header:   embeddedIssuerChainHeader[attest.CollateralTCBInfo],
			response: responses[attest.CollateralTCBInfo],
		}
	}

	// THE ROOT CA CRL'S URL IS NOT A CONSTANT. go-tdx-guest reads it from
	// the CRLDistributionPoints of the QE identity issuer chain's ROOT
	// certificate — i.e. out of the very chain we are about to serve — so
	// the only way to know which URL to answer on is to look inside it.
	// Hardcoding Intel's current one would work until Intel reissues that
	// certificate, and the failure would be a verification that hangs on
	// an unanswered URL rather than anything named.
	certs, err := attest.QEIdentityIssuerCertificates(c)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoUsableCarriedCollateral, err)
	}
	root := certs[len(certs)-1]
	if len(root.CRLDistributionPoints) == 0 {
		return nil, fmt.Errorf("%w: the QE identity issuer root names no CRL distribution point, "+
			"so the root CA CRL could not be served", ErrNoUsableCarriedCollateral)
	}
	for _, u := range root.CRLDistributionPoints {
		// No issuer-chain header: go-tdx-guest reads only the body here,
		// validating the list against the root it has already pinned.
		byURL[u] = embeddedAnswer{response: responses[attest.CollateralRootCACRL]}
	}

	return &embeddedGetter{byURL: byURL}, nil
}

func (g *embeddedGetter) getWithContext(ctx context.Context, url string) (map[string][]string, []byte, error, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	resp, ok := g.byURL[url]
	if !ok {
		return nil, nil, nil, fmt.Errorf("%w: this bundle covers no artifact at %s",
			ErrNoUsableCarriedCollateral, url)
	}
	header := map[string][]string{}
	if resp.header != "" {
		header[resp.header] = []string{resp.response.IssuerChain}
	}
	// No staleCause: nothing here came from OUR cache, so the stale
	// diagnostic would be a false report about our link to Intel. The
	// weaker provenance of this path is reported by the caller, which is
	// the only layer that knows the set came from the node.
	return header, resp.response.Body, nil, nil
}

// VerifyTDXQuoteChainCarried verifies a quote against collateral the
// NODE carried, for use only when Intel's PCS and our own cache have both
// come up empty.
//
// TWO GUARDS STAND IN FOR requireCollateralFetched, which is INERT on
// this path — not skipped. The call still runs (this goes through
// verifyTDXQuoteChainWith like every other verification) but it counts
// getter calls, and the embedded getter always answers at least one, so
// its counter is positive while zero Intel collateral was consulted. It
// would report "collateral was gathered" about a verification that asked
// Intel for nothing. Complete() and CollateralFreshEnough are what this
// path CAN assert — every document present (a partial set is a check that
// would not run) and none of them older than attest's floor.
func VerifyTDXQuoteChainCarried(ctx context.Context, quote []byte, c *inject.TEECollateral) error {
	if !c.Complete() {
		return fmt.Errorf("%w: the bundle carries no complete set", ErrNoUsableCarriedCollateral)
	}
	if !attest.CollateralFreshEnough(c, time.Now(), attest.EmbeddedCollateralMaxAge) {
		return fmt.Errorf("%w: the carried set is older than %v, which is the point past which "+
			"an operator's choice of vintage stops being one we will accept",
			ErrNoUsableCarriedCollateral, attest.EmbeddedCollateralMaxAge)
	}
	getter, err := newEmbeddedGetter(quote, c)
	if err != nil {
		return err
	}
	// No timeout wrapper: this path performs no I/O — the getter is a map —
	// and verifyTDXQuoteChainWith applies CollateralTimeout itself. A second
	// one here was decorative, and a decorative deadline on a hermetic path
	// is the kind of thing a later reader mistakes for a network boundary.
	_, err = verifyTDXQuoteChainWith(ctx, quote, getter)
	return err
}
