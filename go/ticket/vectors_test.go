/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package ticket_test

// Cross-impl byte-parity test. Generates / verifies
// proto/testdata/vectors.json — a language-neutral fixture that pins
// down the byte-level output of every signed or AAD-bound primitive in
// proto/go/wire and proto/go/ticket. proto/ts loads the same file and
// asserts byte equality, so any drift in canonical bytes, AAD layout,
// admission-tag formula, or signing digests fails on both sides
// regardless of who introduced it.
//
// To regenerate after an intentional change:
//
//   cd proto/go && go test ./ticket -run TestVectors -update
//
// Without -update, this test asserts the on-disk file matches what
// the current code produces and fails with a regen hint otherwise.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

var updateVectors = flag.Bool("update", false, "regenerate proto/testdata/vectors.json")

const vectorsPath = "../../testdata/vectors.json"

type aadVector struct {
	TxID        string  `json:"tx_id"`
	TicketID    string  `json:"ticket_id"`
	FrameIndex  *uint64 `json:"frame_index,omitempty"`
	ExpectedHex string  `json:"expected_hex"`
}

type headerAADVector struct {
	TxID        string `json:"tx_id"`
	TicketID    string `json:"ticket_id"`
	Name        string `json:"name"`
	ExpectedHex string `json:"expected_hex"`
}

type admissionTagVector struct {
	KHex        string `json:"k_hex"`
	TicketID    string `json:"ticket_id"`
	TxID        string `json:"tx_id"`
	BodyHex     string `json:"body_hex"`
	ExpectedHex string `json:"expected_hex"`
}

type bodyHashSingleVector struct {
	BodyHex     string `json:"body_hex"`
	ExpectedHex string `json:"expected_hex"`
}

type bodyHashFramesVector struct {
	FramesHex   []string `json:"frames_hex"`
	ExpectedHex string   `json:"expected_hex"`
}

type commitKeyVector struct {
	KHex        string `json:"k_hex"`
	ExpectedHex string `json:"expected_hex"`
}

type ticketVectorEntry struct {
	Value             ticket.Ticket `json:"value"`
	CanonicalBytesHex string        `json:"canonical_bytes_hex"`
	SigDigestHex      string        `json:"sig_digest_hex"`
}

type receiptVectorEntry struct {
	Value             ticket.UsageReceipt `json:"value"`
	CanonicalBytesHex string              `json:"canonical_bytes_hex"`
	SigDigestHex      string              `json:"sig_digest_hex"`
}

// ephemeralVectorEntry pins the canonical bytes + sig digest of an
// EphemeralAdvertisement. Like the reserve entry, OperatorID and NodeID ride
// alongside the value: they are signed *context* passed to
// CanonicalBytes/EphemeralSigDigest (target binding), not struct fields, so
// they would otherwise be invisible in the marshaled vector. Value.Sig stays empty — like the
// ticket / receipt entries, the vector pins only the pre-signature material;
// Sign/Verify is covered by the unit tests.
type ephemeralVectorEntry struct {
	OperatorID        uint64                        `json:"operator_id"`
	NodeID            uint64                        `json:"node_id"`
	Value             ticket.EphemeralAdvertisement `json:"value"`
	CanonicalBytesHex string                        `json:"canonical_bytes_hex"`
	SigDigestHex      string                        `json:"sig_digest_hex"`
}

// reserveVectorEntry pins the canonical bytes + sig digest of the reserve
// request's payer signature. Like the ephemeral entry, OperatorID and NodeID
// ride alongside the value: they are signed *context* passed to
// CanonicalBytes/ReserveSigDigest (target binding), not struct fields, so they
// would otherwise be invisible in the marshaled vector. Value.PayerSig stays
// empty — the vector pins only the pre-signature material; Sign/Verify is
// covered by reserve_test.go.
type reserveVectorEntry struct {
	OperatorID        uint64                `json:"operator_id"`
	NodeID            uint64                `json:"node_id"`
	Value             ticket.ReserveRequest `json:"value"`
	CanonicalBytesHex string                `json:"canonical_bytes_hex"`
	SigDigestHex      string                `json:"sig_digest_hex"`
}

// deploymentVector pins DeploymentID's preimage. Escrow is hex because the
// Solana program id is raw bytes and the Algorand app id enters as be64.
type deploymentVector struct {
	Rail           uint8  `json:"rail"`
	GenesisHashHex string `json:"genesis_hash_hex"`
	EscrowHex      string `json:"escrow_hex"`
	ExpectedHex    string `json:"expected_hex"`
}

// ephemeralV2VectorEntry pins the bound layout SigV2 covers.
type ephemeralV2VectorEntry struct {
	OperatorID        uint64                        `json:"operator_id"`
	NodeID            uint64                        `json:"node_id"`
	Value             ticket.EphemeralAdvertisement `json:"value"`
	CanonicalBytesHex string                        `json:"canonical_bytes_hex"`
	SigDigestHex      string                        `json:"sig_digest_hex"`
}

type algorandAddressVector struct {
	PubkeyHex       string `json:"pubkey_hex"`
	ExpectedAddress string `json:"expected_address"`
}

type vectorsFile struct {
	Version           int                   `json:"version"`
	Comment           string                `json:"comment"`
	AADBodyWithTicket aadVector             `json:"aad_body_with_ticket"`
	AADBodyNoTicket   aadVector             `json:"aad_body_no_ticket"`
	AADFrame          aadVector             `json:"aad_frame"`
	AADHeaderReceipt  headerAADVector       `json:"aad_header_receipt"`
	AADHeaderSettle   headerAADVector       `json:"aad_header_settle_group"`
	AdmissionTag      admissionTagVector    `json:"admission_tag"`
	BodyHashSingle    bodyHashSingleVector  `json:"body_hash_single"`
	BodyHashFrames    bodyHashFramesVector  `json:"body_hash_frames"`
	CommitResponseKey commitKeyVector       `json:"commit_response_key"`
	Ticket            ticketVectorEntry     `json:"ticket"`
	TicketEdge        ticketVectorEntry     `json:"ticket_edge"`
	Receipt           receiptVectorEntry    `json:"receipt"`
	Ephemeral         ephemeralVectorEntry  `json:"ephemeral_advertisement"`
	Reserve           reserveVectorEntry    `json:"reserve_request"`
	AlgorandAddress   algorandAddressVector `json:"algorand_address"`
	// The deployment-bound layouts. The values reuse the unbound entries above
	// with Deployment set to DeploymentAlgorand's id.
	DeploymentAlgorand deploymentVector       `json:"deployment_algorand"`
	DeploymentSolana   deploymentVector       `json:"deployment_solana"`
	TicketV3           ticketVectorEntry      `json:"ticket_v3"`
	ReceiptV3          receiptVectorEntry     `json:"receipt_v3"`
	ReserveV2          reserveVectorEntry     `json:"reserve_request_v2"`
	EphemeralV2        ephemeralV2VectorEntry `json:"ephemeral_advertisement_v2"`
	// DeploymentMalformed are wire values both languages refuse in a ticket,
	// receipt or reserve's "deployment" field. The empty string is among them:
	// unbound is spelled by omitting the field.
	DeploymentMalformed []string `json:"deployment_malformed"`
}

// deploymentMalformed lists wire spellings that UnmarshalText refuses:
// empty, short, all-zero, long, and not base64.
var deploymentMalformed = []string{
	"",
	"AAAA",
	base64.StdEncoding.EncodeToString(make([]byte, 32)),
	base64.StdEncoding.EncodeToString(make([]byte, 33)),
	"not base64!",
}

func buildVectors() *vectorsFile {
	// All inputs are fixed; the whole point is determinism. Changing
	// any of these is fine — the file just needs regenerating with
	// -update — but the *outputs* must be reproducible from the
	// inputs alone.
	const (
		txID     = "TX-VECTOR-001"
		ticketID = "TKT-VECTOR-001"
		// ephemeralAgePubkey is a fixed, well-formed age1… recipient used
		// only as a cross-impl test vector. The EphemeralAdvertisement
		// primitive treats the recipient as opaque length-prefixed bytes
		// (it never parses it), so any valid age1 string works; this one is
		// baked so the canonical bytes / digest are reproducible. Generated
		// once via `go run filippo.io/age/cmd/age-keygen`.
		ephemeralAgePubkey = "age1rc8wp62cfvmldwhm49mdp5lg3gu6qkrs2whhactp0w9nqjk6wp7sl74d8s"
	)

	var k [wire.ResponseKeySize]byte
	for i := range k {
		k[i] = byte(i)
	}

	body := []byte("hello vector body")
	frames := [][]byte{
		[]byte("frame-0"),
		[]byte("frame-1"),
		[]byte("frame-2"),
	}
	framesHex := make([]string, len(frames))
	for i, f := range frames {
		framesHex[i] = hex.EncodeToString(f)
	}

	frameIndex := uint64(7)

	var commitK [wire.ResponseKeySize]byte // all-zero on purpose, distinct vector
	commitSum := ticket.CommitResponseKey(commitK)

	tk := ticket.Ticket{
		TicketID:       base64.StdEncoding.EncodeToString([]byte("sixteen-byte-id!")),
		OperatorID:     42,
		NodeID:         7,
		InputCount:     1234,
		MaxOutputCount: 512,
		InputRate:      2,
		OutputRate:     4,
		MaxPrice:       1234*2 + 512*4,
		MinPrice:       50,
		ExpiresAt:      1_700_000_000,
		Model:          "gpt-4.1-mini",
		Stream:         true,
		CommitK:        base64.StdEncoding.EncodeToString(commitSum[:]),
		// The two usage-type discriminators MUST stay pairwise distinct. They
		// are consecutive single bytes in CanonicalBytes (input then output),
		// so with equal values transposing them is the identity function and
		// the vector pins their width and position but NOT their ORDER — a
		// Go↔TS slot swap would go undetected on every implementation's suite.
		// None/Images is also the exact shape a real image-rate reserve issues
		// (node/internal/server/reserve.go), which was previously unvectored.
		// InputCount / InputRate stay non-zero so their own byte positions
		// remain exercised, even though an image-rate ticket meters no token
		// input; this fixture pins layout, not pricing semantics.
		InputUsageType:  ticket.UsageTypeNone,
		OutputUsageType: ticket.UsageTypeImages,
		// CacheReadRate (v2) is a real discount here: 1 microUSDC/1M vs the
		// InputRate of 2, so the vector exercises the appended tail field.
		CacheReadRate: 1,
	}
	tkCanon := tk.CanonicalBytes()
	tkDigest := ticket.TicketSigDigest(&tk)

	// The shapes the main ticket can't carry: stream false (a buffered image
	// ticket), every string empty (bare zero length prefixes), and a negative
	// expires_at, which the i64 slot must write as its two's-complement u64.
	edge := ticket.Ticket{
		OperatorID:      1,
		NodeID:          2,
		MaxOutputCount:  1,
		OutputRate:      3,
		MaxPrice:        3,
		ExpiresAt:       -1,
		Stream:          false,
		InputUsageType:  ticket.UsageTypeTokens,
		OutputUsageType: ticket.UsageTypeNone,
	}
	edgeCanon := edge.CanonicalBytes()
	edgeDigest := ticket.TicketSigDigest(&edge)

	rc := ticket.UsageReceipt{
		TicketID:          tk.TicketID,
		ActualInputCount:  1100,
		ActualOutputCount: 256,
		AmountCharged:     4500,
		// Non-zero timing halves (ttft 120ms, decode 3400ms) so the vector
		// exercises both ttft_ms and decode_ms round-tripping identically
		// across the Go and TS canonical-bytes implementations.
		TtftMs:   120,
		DecodeMs: 3400,
		BodyHash: strings.Repeat("a", 64),
		// Exercise every v2 field. The three usage-type discriminators MUST stay
		// pairwise distinct: they are three consecutive single bytes in
		// CanonicalBytes (input, output, aux), so equal values in any adjacent
		// pair make transposing that pair the identity function — the vector
		// would pin their width and position but NOT their ORDER. Token input,
		// character-metered output, and an image aux slot give three distinct
		// values while staying a coherent receipt shape.
		InputUsageType:     ticket.UsageTypeTokens,
		OutputUsageType:    ticket.UsageTypeCharacters,
		AuxOutputUsageType: ticket.UsageTypeImages,
		AuxOutputCount:     2,
		// CachedInputCount (v2): 700 of the 1100 input tokens were cache-served
		// (<= ActualInputCount), so the vector exercises the appended tail field.
		CachedInputCount: 700,
	}
	rcCanon := rc.CanonicalBytes()
	rcDigest := ticket.ReceiptSigDigest(&rc)

	// EphemeralAdvertisement: the target (operatorID, nodeID) reuse the
	// ticket's 42/7; expiry reuses the same fixed unix timestamp and issued_at
	// sits 1500s (25m) earlier so the vector exercises a realistic, in-policy
	// signed window. Sig is left empty — the vector pins only canonical bytes +
	// digest, which fold the target ids in (they lead the canonical layout).
	adv := ticket.EphemeralAdvertisement{
		AgePubkey: ephemeralAgePubkey,
		Expiry:    1_700_000_000,
		IssuedAt:  1_700_000_000 - 1500,
	}
	advCanon := adv.CanonicalBytes(42, 7)
	advDigest := ticket.EphemeralSigDigest(&adv, 42, 7)

	var pub [32]byte
	for i := range pub {
		pub[i] = byte(i)
	}
	addr := ticket.EncodeAlgorandAddress(ed25519.PublicKey(pub[:]))

	// ReserveRequest payer-signature vector. Target (operatorID, nodeID) reuse
	// the ticket's 42/7; PayerAddr reuses the deterministic address above;
	// ProxyRecipient reuses the fixed age recipient string; issued_at sits 30s
	// before the fixed timestamp so the vector exercises a realistic in-window
	// value. PayerSig left empty — the vector pins canonical bytes + digest,
	// which fold the target ids in. Image fields are omitted (excluded from
	// canonical bytes by design).
	rr := ticket.ReserveRequest{
		PayerAddr:      addr,
		Model:          "gpt-4.1-mini",
		InputCount:     1234,
		MaxOutputCount: 512,
		Stream:         true,
		ProxyRecipient: ephemeralAgePubkey,
		PayerIssuedAt:  1_700_000_000 - 30,
	}
	rrCanon := rr.CanonicalBytes(42, 7)
	rrDigest := ticket.ReserveSigDigest(&rr, 42, 7)

	// Deployment ids. Genesis bytes count up from 0 and the Solana program id
	// counts down from 0xff, so a byte-order slip in either shows.
	genesis := make([]byte, 32)
	program := make([]byte, 32)
	for i := range genesis {
		genesis[i] = byte(i)
		program[i] = byte(0xff - i)
	}
	const appID = 0x0102030405060708
	depAlgo, err := ticket.AlgorandDeploymentID(genesis, appID)
	if err != nil {
		panic(err)
	}
	depSol, err := ticket.SolanaDeploymentID(genesis, program)
	if err != nil {
		panic(err)
	}

	tkV3 := tk
	tkV3.Deployment = depAlgo
	tkV3Digest := ticket.TicketSigDigest(&tkV3)
	rcV3 := rc
	rcV3.Deployment = depAlgo
	rcV3Digest := ticket.ReceiptSigDigest(&rcV3)
	rrV2 := rr
	rrV2.Deployment = depAlgo
	rrV2Digest := ticket.ReserveSigDigest(&rrV2, 42, 7)
	advV2 := adv
	advV2.Deployment = depAlgo
	advV2Digest := ticket.EphemeralSigDigestV2(&advV2, 42, 7)

	bodyHashSum := wire.BodyHashOfBody(body)
	framesHashSum := wire.BodyHashFromFrames(frames)
	admissionTag := wire.ComputeAdmissionTag(k, ticketID, txID, body)
	bodyAAD := wire.BuildBodyAAD(txID, ticketID)
	bodyAADNoTkt := wire.BuildBodyAAD(txID, "")
	frameAAD := wire.BuildFrameAAD(txID, ticketID, frameIndex)
	headerAADReceipt := wire.BuildHeaderAAD(txID, ticketID, wire.SealedHeaderReceipt)
	headerAADSettle := wire.BuildHeaderAAD(txID, ticketID, wire.SealedHeaderSettleGroup)

	return &vectorsFile{
		Version: 7,
		Comment: "Cross-impl byte-parity vectors for the ZeroSignal protocol. " +
			"Regenerate via: cd proto/go && go test ./ticket -run TestVectors -update. " +
			"Loaded by both proto/go/ticket/vectors_test.go and proto/ts/test/vectors.test.ts.",
		AADBodyWithTicket: aadVector{
			TxID:        txID,
			TicketID:    ticketID,
			ExpectedHex: hex.EncodeToString(bodyAAD),
		},
		AADBodyNoTicket: aadVector{
			TxID:        txID,
			TicketID:    "",
			ExpectedHex: hex.EncodeToString(bodyAADNoTkt),
		},
		AADFrame: aadVector{
			TxID:        txID,
			TicketID:    ticketID,
			FrameIndex:  &frameIndex,
			ExpectedHex: hex.EncodeToString(frameAAD),
		},
		AADHeaderReceipt: headerAADVector{
			TxID:        txID,
			TicketID:    ticketID,
			Name:        wire.SealedHeaderReceipt,
			ExpectedHex: hex.EncodeToString(headerAADReceipt),
		},
		AADHeaderSettle: headerAADVector{
			TxID:        txID,
			TicketID:    ticketID,
			Name:        wire.SealedHeaderSettleGroup,
			ExpectedHex: hex.EncodeToString(headerAADSettle),
		},
		AdmissionTag: admissionTagVector{
			KHex:        hex.EncodeToString(k[:]),
			TicketID:    ticketID,
			TxID:        txID,
			BodyHex:     hex.EncodeToString(body),
			ExpectedHex: hex.EncodeToString(admissionTag),
		},
		BodyHashSingle: bodyHashSingleVector{
			BodyHex:     hex.EncodeToString(body),
			ExpectedHex: hex.EncodeToString(bodyHashSum[:]),
		},
		BodyHashFrames: bodyHashFramesVector{
			FramesHex:   framesHex,
			ExpectedHex: hex.EncodeToString(framesHashSum[:]),
		},
		CommitResponseKey: commitKeyVector{
			KHex:        hex.EncodeToString(commitK[:]),
			ExpectedHex: hex.EncodeToString(commitSum[:]),
		},
		Ticket: ticketVectorEntry{
			Value:             tk,
			CanonicalBytesHex: hex.EncodeToString(tkCanon),
			SigDigestHex:      hex.EncodeToString(tkDigest[:]),
		},
		TicketEdge: ticketVectorEntry{
			Value:             edge,
			CanonicalBytesHex: hex.EncodeToString(edgeCanon),
			SigDigestHex:      hex.EncodeToString(edgeDigest[:]),
		},
		Receipt: receiptVectorEntry{
			Value:             rc,
			CanonicalBytesHex: hex.EncodeToString(rcCanon),
			SigDigestHex:      hex.EncodeToString(rcDigest[:]),
		},
		Ephemeral: ephemeralVectorEntry{
			OperatorID:        42,
			NodeID:            7,
			Value:             adv,
			CanonicalBytesHex: hex.EncodeToString(advCanon),
			SigDigestHex:      hex.EncodeToString(advDigest[:]),
		},
		Reserve: reserveVectorEntry{
			OperatorID:        42,
			NodeID:            7,
			Value:             rr,
			CanonicalBytesHex: hex.EncodeToString(rrCanon),
			SigDigestHex:      hex.EncodeToString(rrDigest[:]),
		},
		AlgorandAddress: algorandAddressVector{
			PubkeyHex:       hex.EncodeToString(pub[:]),
			ExpectedAddress: addr,
		},
		DeploymentAlgorand: deploymentVector{
			Rail:           uint8(ticket.RailAlgorand),
			GenesisHashHex: hex.EncodeToString(genesis),
			EscrowHex:      "0102030405060708",
			ExpectedHex:    hex.EncodeToString(depAlgo[:]),
		},
		DeploymentSolana: deploymentVector{
			Rail:           uint8(ticket.RailSolana),
			GenesisHashHex: hex.EncodeToString(genesis),
			EscrowHex:      hex.EncodeToString(program),
			ExpectedHex:    hex.EncodeToString(depSol[:]),
		},
		TicketV3: ticketVectorEntry{
			Value:             tkV3,
			CanonicalBytesHex: hex.EncodeToString(tkV3.CanonicalBytes()),
			SigDigestHex:      hex.EncodeToString(tkV3Digest[:]),
		},
		ReceiptV3: receiptVectorEntry{
			Value:             rcV3,
			CanonicalBytesHex: hex.EncodeToString(rcV3.CanonicalBytes()),
			SigDigestHex:      hex.EncodeToString(rcV3Digest[:]),
		},
		ReserveV2: reserveVectorEntry{
			OperatorID:        42,
			NodeID:            7,
			Value:             rrV2,
			CanonicalBytesHex: hex.EncodeToString(rrV2.CanonicalBytes(42, 7)),
			SigDigestHex:      hex.EncodeToString(rrV2Digest[:]),
		},
		EphemeralV2: ephemeralV2VectorEntry{
			OperatorID:        42,
			NodeID:            7,
			Value:             advV2,
			CanonicalBytesHex: hex.EncodeToString(advV2.CanonicalBytesV2(42, 7)),
			SigDigestHex:      hex.EncodeToString(advV2Digest[:]),
		},
		DeploymentMalformed: deploymentMalformed,
	}
}

// Every malformed spelling must fail the JSON decode of each object that
// carries the field, not only UnmarshalText on its own.
func TestDeploymentMalformedRefused(t *testing.T) {
	for _, v := range deploymentMalformed {
		field, _ := json.Marshal(map[string]string{"deployment": v})
		for name, dst := range map[string]any{
			"ticket":  &ticket.Ticket{},
			"receipt": &ticket.UsageReceipt{},
			"reserve": &ticket.ReserveRequest{},
		} {
			if err := json.Unmarshal(field, dst); err == nil {
				t.Errorf("%s accepted deployment %q", name, v)
			}
		}
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
		t.Fatalf("read %s: %v\n(run `cd proto/go && go test ./ticket -run TestVectors -update` to generate)", vectorsPath, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s drifted from current Go output\n(run `cd proto/go && go test ./ticket -run TestVectors -update` to regenerate)", vectorsPath)
	}
}
