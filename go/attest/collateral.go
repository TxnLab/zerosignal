/*
 * Copyright (c) 2026. TxnLab Inc.
 * All Rights reserved.
 */

package attest

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/TxnLab/zerosignal/go/inject"
)

// Turning a node-carried collateral set back into the PCS responses a
// DCAP verifier expects, plus the two questions a verifier must answer
// before it will look at one at all.
//
// WHY THIS LIVES IN proto RATHER THAN IN EACH CONSUMER. The decode rules
// below are not obvious from inject.TEECollateral's shape, and each one
// fails in a way that reads as an attestation problem rather than as an
// encoding problem: an issuer chain parses to zero certificates, a CRL
// refuses to parse as DER, a signature stops matching a document whose
// fields all still read back correctly. Getting them wrong in two
// consumers produces two different flavours of "this node cannot be
// verified" with no hint that the node is fine.
//
// What is deliberately NOT here: URLs. A verifier's collateral fetcher
// is keyed by URL, and which URL it asks for is that library's business
// — go-tdx-guest's endpoints and header spellings are go-tdx-guest's,
// not Intel's protocol. Adding a go-tdx-guest dependency to this module
// would also push it onto node, tui, and every future consumer, none of
// which verify quotes. So this package answers in VALUES and the
// consumer keys them.

// EmbeddedCollateralMaxAge is how stale node-carried collateral may be
// before a verifier refuses to fall back to it.
//
// THIS IS THE REASON node-carried collateral is a fallback rather than a
// source. Intel's signature makes the CONTENTS unforgeable and says
// nothing about WHICH validly-signed vintage the node chose to hand
// over, and the vintage is the attack: a platform downgraded to
// OutOfDate by a newer TCB publication still reads UpToDate in the
// previous one, and a PCK certificate revoked since a CRL was issued is
// absent from it. A DCAP verifier enforces only each document's own
// nextUpdate (~30 days for TCB info), so this floor is deliberately
// tighter than Intel's window.
//
// 14 days rejects essentially nothing honest, which was measured rather
// than assumed: two FMSPCs and the global QE identity all carried an
// issueDate of the day they were fetched, with a rolling 30-day
// nextUpdate. Intel RE-ISSUES CONTINUOUSLY, so 30 days is a staleness
// ceiling and never a publication cadence — which also means the
// rollback window is nearly always the full width, not the narrow one
// the shape suggests.
//
// Mirrors EMBEDDED_COLLATERAL_MAX_AGE_MS in
// client/src/operators/tee-verify.ts. Not golden-vectored: the
// TypeScript twin lives in client/, not proto/ts, so there is nothing
// here to vector it against. If that predicate ever moves into proto/ts,
// vectors follow.
const EmbeddedCollateralMaxAge = 14 * 24 * time.Hour

// CollateralArtifact names one of the four documents a DCAP verifier
// fetches. The consumer maps these onto its own library's URLs.
type CollateralArtifact int

const (
	// CollateralTCBInfo is the per-FMSPC TCB info document.
	CollateralTCBInfo CollateralArtifact = iota
	// CollateralQEIdentity is the (platform-independent) QE identity.
	CollateralQEIdentity
	// CollateralPCKCRL is the PCK revocation list for this platform's CA.
	CollateralPCKCRL
	// CollateralRootCACRL is Intel's root CA revocation list.
	CollateralRootCACRL
)

func (a CollateralArtifact) String() string {
	switch a {
	case CollateralTCBInfo:
		return "tcb_info"
	case CollateralQEIdentity:
		return "qe_identity"
	case CollateralPCKCRL:
		return "pck_crl"
	case CollateralRootCACRL:
		return "root_ca_crl"
	}
	return "unknown"
}

// CollateralResponse is one artifact in the shape a PCS would have
// served it: a body, and the issuer chain that would have ridden in a
// response header.
type CollateralResponse struct {
	// IssuerChain is the PEM chain PERCENT-ENCODED, ready to be used as
	// an HTTP header value. Empty for CollateralRootCACRL, which no
	// verifier reads a chain for — it is validated against the root
	// already pinned in the verifier.
	//
	// Encoded rather than raw because that is the form a PCS serves and
	// therefore the form a verifier decodes: PEM's newlines cannot ride
	// an HTTP header, so Intel's mirrors send %0A for them (and %20 for
	// space, %2B for "+"). inject.TEECollateral stores these DECODED, on
	// purpose — see its PCKCRLIssuerChain godoc — so a consumer that
	// passes the stored value through as a header ships a chain that
	// parses to ZERO certificates while looking present in its own logs.
	IssuerChain string

	// Body is the artifact bytes: raw DER for the two CRLs, and the full
	// PCCS JSON envelope for the two signed documents.
	Body []byte
}

// ErrCollateralIncomplete means the set cannot be turned into responses.
var ErrCollateralIncomplete = errors.New("attest: collateral set is unusable")

// CollateralResponses rebuilds the four PCS responses from a carried
// collateral set.
//
// A PARTIAL SET IS AN ABSENT SET, enforced here by Complete() before any
// decoding: accepting eight of nine fields means one check silently does
// not run, which is exactly the shape a node with something to hide
// would engineer. The caller should also have satisfied
// CollateralFreshEnough — this function answers "can these bytes be
// served", never "should they be believed".
func CollateralResponses(c *inject.TEECollateral) (map[CollateralArtifact]CollateralResponse, error) {
	if !c.Complete() {
		return nil, fmt.Errorf("%w: incomplete or absent", ErrCollateralIncomplete)
	}

	// THE ENVELOPE IS REASSEMBLED BY CONCATENATION, NOT BY MARSHALLING A
	// MAP. Intel signs the inner document's exact bytes, and
	// encoding/json sorts map keys — so a decode/re-encode round trip
	// produces a document whose every field reads back correctly and
	// whose signature verifies nowhere. json.RawMessage keeps the bytes
	// the signature covers. (The JS reference implementation round-trips
	// through JSON.parse/stringify and survives only because that
	// preserves insertion order; do not read it as license.)
	tcb, err := signedEnvelope("tcbInfo", c.TCBInfo, c.TCBInfoSignature)
	if err != nil {
		return nil, fmt.Errorf("%w: tcb_info: %v", ErrCollateralIncomplete, err)
	}
	qe, err := signedEnvelope("enclaveIdentity", c.QEIdentity, c.QEIdentitySignature)
	if err != nil {
		return nil, fmt.Errorf("%w: qe_identity: %v", ErrCollateralIncomplete, err)
	}

	// Both CRLs travel hex-encoded and are consumed as raw DER — a
	// verifier hands the body straight to an X.509 CRL parser, so hex
	// text reaches it as a parse failure indistinguishable from a
	// corrupt list.
	pckCRL, err := hex.DecodeString(strings.TrimSpace(c.PCKCRL))
	if err != nil {
		return nil, fmt.Errorf("%w: pck_crl is not hex: %v", ErrCollateralIncomplete, err)
	}
	rootCRL, err := hex.DecodeString(strings.TrimSpace(c.RootCACRL))
	if err != nil {
		return nil, fmt.Errorf("%w: root_ca_crl is not hex: %v", ErrCollateralIncomplete, err)
	}

	return map[CollateralArtifact]CollateralResponse{
		CollateralTCBInfo: {
			IssuerChain: url.QueryEscape(c.TCBInfoIssuerChain),
			Body:        tcb,
		},
		CollateralQEIdentity: {
			IssuerChain: url.QueryEscape(c.QEIdentityIssuerChain),
			Body:        qe,
		},
		CollateralPCKCRL: {
			IssuerChain: url.QueryEscape(c.PCKCRLIssuerChain),
			Body:        pckCRL,
		},
		CollateralRootCACRL: {
			Body: rootCRL,
		},
	}, nil
}

// signedEnvelope rebuilds `{"<field>":<doc>,"signature":"<sig>"}` with
// the document's bytes untouched.
//
// doc MUST be the BARE inner document, per SPEC §3e — which is also what
// the node produces, since its splitSigned extracts env["tcbInfo"]. An
// already-wrapped document is refused rather than wrapped again: a
// double-wrapped envelope is well-formed JSON that every structural check
// passes, and go-tdx-guest's bodyToRawMessage would hand the signature
// check the inner {"tcbInfo":{…}} object, which verifies nowhere. The
// failure would surface as a chain error — this node's evidence is bad —
// for what is our own encoding mistake, in the file whose whole job is
// keeping those two apart.
func signedEnvelope(field, doc, sig string) ([]byte, error) {
	if !json.Valid([]byte(doc)) {
		return nil, errors.New("the signed document is not valid JSON")
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(doc), &probe); err != nil {
		// Not an object at all. json.Valid accepts `5`, `null`, `[]` and
		// `"hi"`, each of which builds a well-formed envelope carrying no
		// document — refused here rather than three layers later.
		return nil, fmt.Errorf("the signed document is not a JSON object: %w", err)
	}
	// `null` unmarshals into a map WITHOUT error, leaving it nil — so the
	// error check above does not cover it, and it would build an envelope
	// reading {"tcbInfo":null,"signature":"…"}.
	if probe == nil {
		return nil, errors.New("the signed document is JSON null, not a document")
	}
	if _, wrapped := probe[field]; wrapped {
		return nil, fmt.Errorf("the signed document already carries a %q wrapper; "+
			"this field is the bare inner document, per SPEC §3e", field)
	}
	name, err := json.Marshal(field)
	if err != nil {
		return nil, err
	}
	// THE SIGNATURE'S ENCODING IS CHECKED HERE OR NOWHERE. Both consumers
	// hex-decode it, and the node's splitSigned only tests it for
	// non-emptiness — so a whitespace-padded or non-hex signature would
	// travel all the way to the verifier and surface as a chain failure,
	// i.e. as an accusation against the node, for a malformed field we
	// could have named. It is the one member of the set nothing else
	// validates.
	if _, err := hex.DecodeString(sig); err != nil {
		return nil, fmt.Errorf("the %s signature is not hex: %w", field, err)
	}
	sigJSON, err := json.Marshal(sig)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(doc)+len(sig)+32)
	out = append(out, '{')
	out = append(out, name...)
	out = append(out, ':')
	out = append(out, doc...)
	out = append(out, `,"signature":`...)
	out = append(out, sigJSON...)
	out = append(out, '}')
	return out, nil
}

// QEIdentityIssuerCertificates parses the QE identity issuer chain into
// its certificates, leaf first.
//
// Exposed because a verifier's ROOT CA CRL URL is not a constant: it is
// read out of the CRLDistributionPoints of that chain's root
// certificate, i.e. out of the very chain being supplied, so a consumer
// serving a carried set has to look inside it to know what URL to answer
// on.
func QEIdentityIssuerCertificates(c *inject.TEECollateral) ([]*x509.Certificate, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: absent", ErrCollateralIncomplete)
	}
	return parsePEMChain(c.QEIdentityIssuerChain)
}

func parsePEMChain(chain string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(chain)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("issuer chain: %w", err)
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		// The signature of a chain that was percent-encoded when it
		// should have been decoded, or decoded twice. Worth naming,
		// because every downstream symptom is an attestation failure.
		return nil, fmt.Errorf("%w: issuer chain parsed to zero certificates", ErrCollateralIncomplete)
	}
	return out, nil
}

// CollateralFreshEnough reports whether every document in the set was
// published recently enough to be trusted as a fallback.
//
// FAIL-CLOSED: an unparseable or undated document is not fresh. What it
// gates is a convenience, so refusing costs only the "collateral
// unreachable" outcome that would otherwise have been reported anyway.
//
// ALL FOUR DOCUMENTS, because the rollback it bounds is per-document: a
// node can pair freshly-dated TCB info with an older, still validly
// signed CRL that predates the revocation of its own PCK certificate.
// Checking the newest of them would let the other three be anything.
//
// Mirrors collateralFreshEnough in client/src/operators/tee-verify.ts.
func CollateralFreshEnough(c *inject.TEECollateral, now time.Time, maxAge time.Duration) bool {
	if !c.Complete() {
		return false
	}
	dates := []func() (time.Time, bool){
		func() (time.Time, bool) { return issuedAt(c.TCBInfo, "tcbInfo") },
		func() (time.Time, bool) { return issuedAt(c.QEIdentity, "enclaveIdentity") },
		func() (time.Time, bool) { return crlThisUpdate(c.PCKCRL) },
		func() (time.Time, bool) { return crlThisUpdate(c.RootCACRL) },
	}
	for _, at := range dates {
		t, ok := at()
		if !ok {
			return false
		}
		// A FUTURE issueDate is refused too. It is either a clock
		// problem or a document that cannot have been published yet,
		// and "now minus a future instant" is negative, which would
		// otherwise read as fresher than anything real.
		if t.After(now) || now.Sub(t) > maxAge {
			return false
		}
	}
	return true
}

// issuedAt reads issueDate off a signed collateral document.
//
// THE BARE SHAPE ONLY, and the wrapper parameter is what it REFUSES
// rather than what it unwraps. An earlier version accepted both "matching
// what DCAP verifiers themselves accept", which was wrong twice: the
// consumers take this field bare (go-tdx-guest wants the wrapper on the
// envelope signedEnvelope builds, dcap-qvl takes the string opaquely),
// and accepting the wrapped shape here made this the one gate that could
// have named the double-wrap signedEnvelope would then produce. Two
// helpers disagreeing about one field's shape is how a set passes every
// check and verifies nowhere.
func issuedAt(doc, wrapper string) (time.Time, bool) {
	var inner map[string]json.RawMessage
	if err := json.Unmarshal([]byte(doc), &inner); err != nil {
		return time.Time{}, false
	}
	if _, wrapped := inner[wrapper]; wrapped {
		return time.Time{}, false
	}
	raw, ok := inner["issueDate"]
	if !ok {
		return time.Time{}, false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// crlThisUpdate reads thisUpdate off a hex-encoded DER CRL. Dating only
// — validating the CRL is the verifier's job.
func crlThisUpdate(hexDER string) (time.Time, bool) {
	der, err := hex.DecodeString(strings.TrimSpace(hexDER))
	if err != nil || len(der) == 0 {
		return time.Time{}, false
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return time.Time{}, false
	}
	if crl.ThisUpdate.IsZero() {
		return time.Time{}, false
	}
	return crl.ThisUpdate, true
}

// oidSGXExtension is Intel's SGX extension on a PCK certificate;
// oidPCKFMSPC is the FMSPC entry inside it.
var (
	oidSGXExtension = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}
	oidPCKFMSPC     = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 4}
)

// pckFMSPCLen is the width of an FMSPC, per Intel's PCK certificate
// specification.
const pckFMSPCLen = 6

// PCKPlatformID reads the platform identifiers a quote's collateral is
// keyed by out of the leaf PCK certificate embedded in the quote: the
// FMSPC (which TCB info describes this platform) and the CA type (which
// PCK CRL covers it).
//
// HAND-ROLLED RATHER THAN TAKEN FROM go-tdx-guest, and this module could
// not use that library anyway. But the choice would stand regardless:
// its pcs.PckCertificateExtensions asserts an EXACT extension count, so
// any future addition to Intel's certificate profile turns into "this
// platform has no identifiers" rather than into a parse that skips
// something it does not recognize.
//
// Appropriate here for a reason that is NOT true elsewhere in this
// package: these bytes only decide which documents to FETCH. A wrong
// answer yields collateral that does not match the quote, and the
// verification fails closed. Contrast SplitReportData, where the bytes
// ARE the claim being checked.
func PCKPlatformID(quote []byte) (fmspc, ca string, err error) {
	chain, ok := QuotePCKCertChain(quote)
	if !ok {
		return "", "", errors.New("attest: the quote carries no PCK certificate chain")
	}
	return pckPlatformIDFromChain(chain)
}

func pckPlatformIDFromChain(pemChain []byte) (fmspc, ca string, err error) {
	block, _ := pem.Decode(pemChain)
	if block == nil {
		return "", "", errors.New("attest: PCK chain is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("attest: leaf PCK certificate: %w", err)
	}

	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidSGXExtension) {
			continue
		}
		var seq []asn1.RawValue
		if _, uerr := asn1.Unmarshal(ext.Value, &seq); uerr != nil {
			return "", "", fmt.Errorf("attest: SGX extension: %w", uerr)
		}
		for _, el := range seq {
			var kv struct {
				Type  asn1.ObjectIdentifier
				Value asn1.RawValue
			}
			// Entries carry heterogeneous value shapes (the TCB entry
			// is a nested SEQUENCE), so an entry this struct cannot
			// read is skipped rather than failing the walk.
			if _, uerr := asn1.Unmarshal(el.FullBytes, &kv); uerr != nil {
				continue
			}
			// An FMSPC is exactly six bytes. Length-checked so a walk
			// that landed on some other extension's value produces a
			// refusal rather than a plausible query parameter — a PCCS
			// would answer 404 or, worse, about another platform.
			if kv.Type.Equal(oidPCKFMSPC) && len(kv.Value.Bytes) == pckFMSPCLen {
				fmspc = strings.ToUpper(hex.EncodeToString(kv.Value.Bytes))
			}
		}
	}
	if fmspc == "" {
		return "", "", errors.New("attest: leaf PCK certificate carries no FMSPC")
	}
	return fmspc, pckIssuerCA(cert.Issuer.CommonName), nil
}

// pckIssuerCA maps the PCK issuer's common name onto the `ca` value its
// CRL is served under.
//
// Defaults to processor, matching dcap-qvl. It is DELIBERATELY looser
// than go-tdx-guest, which is worth stating precisely because an earlier
// version of this comment claimed both agreed: that library's
// extractCaFromPckCert does an EXACT compare against the two issuer CNs
// and returns ErrPckCertCANil for anything else — it does not default at
// all. So on a certificate neither recognizes, go-tdx-guest refuses
// before this answer is ever consulted, and dcap-qvl fetches the
// processor CRL.
//
// Guessing is safe here in a way it would not be elsewhere: the wrong
// CRL simply is not the one covering this platform's PCK certificate, so
// the verifier refuses — visible as a failed attestation rather than as
// a pass on an unchecked revocation.
func pckIssuerCA(commonName string) string {
	if strings.Contains(commonName, "Platform") {
		return "platform"
	}
	return "processor"
}
