/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/ticket"
)

func testDeployment(t *testing.T, fill byte) ticket.DeploymentID {
	t.Helper()
	d, err := ticket.AlgorandDeploymentID(bytes.Repeat([]byte{fill}, 32), 1001)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// deploymentReserve runs one reserve against a harness node advertising
// nodeVersion, whose ticket is bound to answerWith (zero: legacy). It returns
// the request the node saw and the reserve's error.
func deploymentReserve(t *testing.T, payer ticket.DeploymentID, nodeVersion string, answerWith func(seen ticket.ReserveRequest) ticket.DeploymentID) (ticket.ReserveRequest, error) {
	t.Helper()
	payerAddr, _, payerPriv, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var seen ticket.ReserveRequest
	h := newReserveHarness(t, func(http.ResponseWriter, *http.Request) {})
	h.operator.ProtoVersion = nodeVersion
	h.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = h.decodeReserve(t, r)
		resp := h.issueValidTicket(t, seen)
		if d := answerWith(seen); !d.IsZero() {
			resp.Ticket.Deployment = d
			if err := resp.Ticket.Sign(context.Background(), rawKeyBytesSigner{addr: h.signAddr, priv: h.signKey}, h.signAddr); err != nil {
				t.Fatal(err)
			}
		}
		writeSealedReserve(t, w, resp, seen.ProxyRecipient)
	})
	req := sampleReserveReq()
	req.PayerAddr = payerAddr
	c := &HTTPReserveClient{
		HTTPClient: http.DefaultClient,
		Signer:     rawKeyBytesSigner{addr: payerAddr, priv: payerPriv},
		Deployment: payer,
	}
	_, err = c.Reserve(context.Background(), h.operator, req, nil)
	return seen, err
}

func echo(seen ticket.ReserveRequest) ticket.DeploymentID { return seen.Deployment }

func fixed(d ticket.DeploymentID) func(ticket.ReserveRequest) ticket.DeploymentID {
	return func(ticket.ReserveRequest) ticket.DeploymentID { return d }
}

func TestReserve_NamesDeploymentToANewNode(t *testing.T) {
	mine := testDeployment(t, 1)
	seen, err := deploymentReserve(t, mine, "9.13", echo)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if seen.Deployment != mine {
		t.Fatalf("node saw deployment %v, want %v", seen.Deployment, mine)
	}
	// The payer signature is over the bound layout: the node verifies it
	// with its own deployment and no legacy allowance.
	pub, err := ticket.DecodeAlgorandAddress(seen.PayerAddr)
	if err != nil {
		t.Fatal(err)
	}
	if err := seen.VerifyFor(pub, 1, 0, time.Now(), ticket.DefaultReserveSkew, mine, false); err != nil {
		t.Fatalf("node-side verify of the bound reserve: %v", err)
	}
}

func TestReserve_NewNodeMustAnswerBound(t *testing.T) {
	mine := testDeployment(t, 1)
	_, err := deploymentReserve(t, mine, "9.13", fixed(ticket.DeploymentID{}))
	if !errors.Is(err, ticket.ErrLegacySignature) {
		t.Fatalf("legacy ticket from a node we asked for a bound one: %v, want ErrLegacySignature", err)
	}
	_, err = deploymentReserve(t, mine, "9.13", fixed(testDeployment(t, 2)))
	if !errors.Is(err, ticket.ErrDeploymentMismatch) {
		t.Fatalf("ticket bound to another deployment: %v, want ErrDeploymentMismatch", err)
	}
}

// An older node never sees the field, and its legacy ticket passes. A ticket
// it binds anyway must still name our deployment.
func TestReserve_OlderNodeKeepsLegacy(t *testing.T) {
	mine := testDeployment(t, 1)
	for _, version := range []string{"9.12", "", "not-a-version"} {
		seen, err := deploymentReserve(t, mine, version, fixed(ticket.DeploymentID{}))
		if err != nil {
			t.Fatalf("version %q: Reserve: %v", version, err)
		}
		if !seen.Deployment.IsZero() {
			t.Fatalf("version %q: payer named its deployment to a node that predates it", version)
		}
	}
	if _, err := deploymentReserve(t, mine, "9.12", fixed(mine)); err != nil {
		t.Fatalf("older node, ticket bound to us: %v", err)
	}
	if _, err := deploymentReserve(t, mine, "9.12", fixed(testDeployment(t, 2))); !errors.Is(err, ticket.ErrDeploymentMismatch) {
		t.Fatalf("older node, ticket bound elsewhere: %v, want ErrDeploymentMismatch", err)
	}
}

func TestReserve_PayerWithoutDeploymentStaysLegacy(t *testing.T) {
	seen, err := deploymentReserve(t, ticket.DeploymentID{}, "9.13", fixed(ticket.DeploymentID{}))
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if !seen.Deployment.IsZero() {
		t.Fatal("a payer with no deployment named one")
	}
}

// The receipt check follows the ticket: a bound ticket needs a receipt bound to
// the same deployment, and an unbound ticket a legacy receipt.
func TestVerifyReceipt_FollowsTicketBinding(t *testing.T) {
	mine, other := testDeployment(t, 1), testDeployment(t, 2)
	addr, pub, priv, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	signer := rawKeyBytesSigner{addr: addr, priv: priv}
	op := Operator{TicketSigningKey: pub}
	receipt := func(d ticket.DeploymentID) *ticket.UsageReceipt {
		r := &ticket.UsageReceipt{TicketID: "AAAAAAAAAAAAAAAAAAAAAA==", AmountCharged: 1, BodyHash: string(bytes.Repeat([]byte{'a'}, 64)), Deployment: d}
		if err := r.Sign(context.Background(), signer, addr); err != nil {
			t.Fatal(err)
		}
		return r
	}
	cases := []struct {
		name    string
		tkt     ticket.DeploymentID
		rcpt    ticket.DeploymentID
		wantErr error
	}{
		{"bound ticket, bound receipt", mine, mine, nil},
		{"bound ticket, legacy receipt", mine, ticket.DeploymentID{}, ticket.ErrLegacySignature},
		{"bound ticket, receipt bound elsewhere", mine, other, ticket.ErrDeploymentMismatch},
		{"legacy ticket, legacy receipt", ticket.DeploymentID{}, ticket.DeploymentID{}, nil},
		{"legacy ticket, bound receipt", ticket.DeploymentID{}, mine, ticket.ErrDeploymentMismatch},
	}
	for _, c := range cases {
		err := VerifyReceipt(ReceiptCheck{
			Ticket:   &ticket.Ticket{TicketID: "AAAAAAAAAAAAAAAAAAAAAA==", MaxPrice: 10, Deployment: c.tkt},
			Operator: op,
			Receipt:  receipt(c.rcpt),
		})
		var sigErr error
		var re *ReceiptError
		if errors.As(err, &re) && re.Violation == ReceiptViolationSig {
			sigErr = err
		}
		switch {
		case c.wantErr == nil && sigErr != nil:
			t.Errorf("%s: %v", c.name, sigErr)
		case c.wantErr != nil && !errors.Is(sigErr, c.wantErr):
			t.Errorf("%s: %v, want %v", c.name, err, c.wantErr)
		}
	}
}
