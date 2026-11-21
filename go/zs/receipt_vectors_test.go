/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/receipt_check_vectors.json: the payer's
// verdict on a node's usage receipt (VerifyReceipt), which the TS SDK mirrors
// as verifyReceipt in sdk/src/verify.ts, and whether that verdict bars the
// node (receiptExclusion in dispatch.go and sdk/src/receipt-check.ts). The
// violation decides what the turn does with the receipt and the exclusion
// whether the node is routed to again, so both SDKs must reach the same ones
// for the same receipt and ticket. That checkReceipt acts on the exclusion is
// tested per language.
//
//	cd proto/go && go test ./zs -run TestReceiptCheckVectors -update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/TxnLab/zerosignal/go/ticket"
)

const receiptCheckVectorsPath = "../../testdata/receipt_check_vectors.json"

type receiptCheckScenario struct {
	Name    string              `json:"name"`
	Ticket  ticket.Ticket       `json:"ticket"`
	Receipt ticket.UsageReceipt `json:"receipt"`
	// SigningKey is the node's ed25519 public key, base64.
	SigningKey string `json:"signing_key"`
	// ComputedHash is the payer's sha256 of what the node delivered, hex.
	ComputedHash string `json:"computed_hash"`
	// Violation is the refusing check's ReceiptViolation, or "" when the
	// receipt verifies.
	Violation string `json:"violation"`
	// Exclusion is the NodeExcluded reason the refusal bars the node for
	// (receiptExclusion), or "" when it bars none.
	Exclusion string `json:"exclusion"`
}

func receiptCheckScenarios(t *testing.T) []receiptCheckScenario {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i*7 + 3)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	addr := ticket.EncodeAlgorandAddress(pub)
	signer := rawKeyBytesSigner{addr: addr, priv: priv}

	const (
		payers = "c2l4dGVlbi1ieXRlLWlkIQ==" // "sixteen-byte-id!"
		other  = "YW5vdGhlci10aWNrZXQhIQ==" // "another-ticket!!"
		// payers' bytes with non-zero padding bits, which Go's decoder reads
		// as the same 16 bytes.
		payersLoose = "c2l4dGVlbi1ieXRlLWlkIR=="
	)
	delivered := sha256.Sum256([]byte("hello world"))
	// Every scenario is bound to mine unless it says otherwise: an unbound
	// ticket or receipt is refused before any other check could speak.
	mine, elsewhere := testDeployment(t, 1), testDeployment(t, 2)

	base := func(name string) receiptCheckScenario {
		return receiptCheckScenario{
			Name: name,
			Ticket: ticket.Ticket{
				TicketID: payers, OperatorID: 42, NodeID: 7, InputCount: 100, MaxOutputCount: 100,
				InputRate: 1_000_000, OutputRate: 2_000_000, CacheReadRate: 1_000_000,
				MaxPrice: 5000, MinPrice: 100, ExpiresAt: 1_700_000_000, Model: "m", Stream: true,
				CommitK:        base64.StdEncoding.EncodeToString(make([]byte, 32)),
				InputUsageType: ticket.UsageTypeTokens, OutputUsageType: ticket.UsageTypeTokens,
				Deployment: mine,
			},
			Receipt: ticket.UsageReceipt{
				TicketID: payers, ActualInputCount: 42, ActualOutputCount: 17, AmountCharged: 2600,
				TtftMs: 120, DecodeMs: 900,
				InputUsageType: ticket.UsageTypeTokens, OutputUsageType: ticket.UsageTypeTokens,
				Deployment: mine,
			},
			SigningKey:   base64.StdEncoding.EncodeToString(pub),
			ComputedHash: hex.EncodeToString(delivered[:]),
		}
	}
	var out []receiptCheckScenario
	// edit runs before signing; tamper after it.
	add := func(name, violation, exclusion string, edit, tamper func(*receiptCheckScenario)) {
		sc := base(name)
		sc.Receipt.SetBodyHashBytes(delivered)
		if edit != nil {
			edit(&sc)
		}
		if err := sc.Receipt.Sign(context.Background(), signer, addr); err != nil {
			t.Fatal(err)
		}
		if tamper != nil {
			tamper(&sc)
		}
		sc.Violation, sc.Exclusion = violation, exclusion
		out = append(out, sc)
	}
	receiptNames := func(id string) func(*receiptCheckScenario) {
		return func(sc *receiptCheckScenario) { sc.Receipt.TicketID = id }
	}
	bothName := func(id string) func(*receiptCheckScenario) {
		return func(sc *receiptCheckScenario) { sc.Ticket.TicketID, sc.Receipt.TicketID = id, id }
	}
	const barred = exclusionReceiptForAnotherTicket

	add("a receipt naming the payer's ticket verifies", "", "", nil, nil)
	add("a receipt the node signed for another ticket is refused and bars the node", "sig", barred, receiptNames(other), nil)
	// The node signed another spelling than the one it issued the ticket in.
	add("the payer's ticket bytes with non-zero padding bits are refused and bar the node", "sig", barred, receiptNames(payersLoose), nil)
	add("the payer's ticket id unpadded is refused and bars the node", "sig", barred, receiptNames("c2l4dGVlbi1ieXRlLWlkIQ"), nil)
	// Go's decoder skips line breaks, so only the string compare refuses these.
	add("the payer's ticket id with a trailing newline is refused and bars the node", "sig", barred, receiptNames(payers+"\n"), nil)
	add("the payer's ticket id with a line break inside is refused and bars the node", "sig", barred, receiptNames(payers[:12]+"\r\n"+payers[12:]), nil)
	add("the payer's ticket id with a leading space is refused and bars the node", "sig", barred, receiptNames(" "+payers), nil)
	// The payer's own id is at fault here, not the node's receipt.
	add("a ticket id not in its canonical spelling refuses even the receipt echoing it, barring no node", "sig", "", bothName(payersLoose), nil)
	add("a ticket id of 17 bytes refuses even the receipt echoing it, barring no node", "sig", "", bothName("dGlja2V0LXhvcnZvenp6MDA="), nil)
	add("an empty ticket id refuses even the receipt echoing it, barring no node", "sig", "", bothName(""), nil)
	add("a non-canonical ticket id bars no node even when the receipt names another ticket", "sig", "",
		func(sc *receiptCheckScenario) { sc.Ticket.TicketID, sc.Receipt.TicketID = payersLoose, other }, nil)
	// The ticket check precedes the two that act on the receipt: amount pins
	// its figure and journals it, body_hash also protests with it.
	add("another ticket's receipt is refused before its body_hash would drive a protest", "sig", barred,
		func(sc *receiptCheckScenario) {
			sc.Receipt.TicketID = other
			sc.Receipt.SetBodyHashBytes(sha256.Sum256([]byte("other content")))
		}, nil)
	add("another ticket's receipt is refused before its charge would be pinned", "sig", barred,
		func(sc *receiptCheckScenario) { sc.Receipt.TicketID, sc.Receipt.AmountCharged = other, 5001 }, nil)
	add("a receipt altered after signing is refused, barring no node", "sig", "", nil,
		func(sc *receiptCheckScenario) { sc.Receipt.AmountCharged = 2601 })
	// Without a signature that verifies, nothing shows the node wrote it.
	add("another ticket's receipt altered after signing bars no node", "sig", "", receiptNames(other),
		func(sc *receiptCheckScenario) { sc.Receipt.AmountCharged = 2601 })
	add("a charge above max_price is refused as amount", "amount", "",
		func(sc *receiptCheckScenario) { sc.Receipt.AmountCharged = 5001 }, nil)
	add("a cached input count above the actual input count is refused as amount", "amount", "",
		func(sc *receiptCheckScenario) { sc.Receipt.CachedInputCount = sc.Receipt.ActualInputCount + 1 }, nil)
	bound := func(tkt, rcpt ticket.DeploymentID) func(*receiptCheckScenario) {
		return func(sc *receiptCheckScenario) { sc.Ticket.Deployment, sc.Receipt.Deployment = tkt, rcpt }
	}
	add("a bound ticket's receipt bound to the same deployment verifies", "", "", bound(mine, mine), nil)
	add("a bound ticket's legacy receipt is refused", "sig", "", bound(mine, ticket.DeploymentID{}), nil)
	add("a bound ticket's receipt bound elsewhere is refused", "sig", "", bound(mine, elsewhere), nil)
	add("a legacy ticket's bound receipt is refused", "sig", "", bound(ticket.DeploymentID{}, mine), nil)
	add("a legacy ticket's legacy receipt is refused", "sig", "", bound(ticket.DeploymentID{}, ticket.DeploymentID{}), nil)
	add("a body_hash other than the delivered content's is refused as body_hash", "body_hash", "",
		func(sc *receiptCheckScenario) { sc.Receipt.SetBodyHashBytes(sha256.Sum256([]byte("other content"))) }, nil)
	return out
}

func TestReceiptCheckVectors(t *testing.T) {
	scenarios := receiptCheckScenarios(t)
	for _, sc := range scenarios {
		pub, err := base64.StdEncoding.DecodeString(sc.SigningKey)
		if err != nil {
			t.Fatal(err)
		}
		var computed [32]byte
		if _, err := hex.Decode(computed[:], []byte(sc.ComputedHash)); err != nil {
			t.Fatal(err)
		}
		tkt, rcpt := sc.Ticket, sc.Receipt
		err = VerifyReceipt(ReceiptCheck{Ticket: &tkt, Operator: Operator{TicketSigningKey: pub}, Receipt: &rcpt, ComputedHash: computed})
		got := ""
		if err != nil {
			re, ok := AsReceiptError(err)
			if !ok {
				t.Fatalf("%s: %v is not a ReceiptError", sc.Name, err)
			}
			got = re.Violation.String()
		}
		if got != sc.Violation {
			t.Errorf("%s: violation %q (%v), want %q", sc.Name, got, err, sc.Violation)
		}
		if got := receiptExclusion(err); got != sc.Exclusion {
			t.Errorf("%s: exclusion %q (%v), want %q", sc.Name, got, err, sc.Exclusion)
		}
	}

	f := struct {
		Comment   string                 `json:"comment"`
		Scenarios []receiptCheckScenario `json:"scenarios"`
	}{
		Comment:   "Generated by proto/go/zs TestReceiptCheckVectors. The payer's verdict on a node's usage receipt (VerifyReceipt / verifyReceipt): the refusing check's violation, or \"\" when the receipt verifies, and the NodeExcluded reason that refusal bars the node for (receiptExclusion in both SDKs), or \"\" when it bars none. signing_key is the node's ed25519 public key in base64; computed_hash is the payer's sha256 of the delivered content in hex.",
		Scenarios: scenarios,
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(receiptCheckVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(receiptCheckVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatal("receipt_check_vectors.json is stale; regenerate with -update")
	}
}
