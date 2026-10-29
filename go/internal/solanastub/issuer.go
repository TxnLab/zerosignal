/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solanastub

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/TxnLab/zerosignal/go/freecredit"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// The localnet free-credit issuer, whose public key is the localnet preset's.
// Its private half is committed, so a node trusts it only on a loopback RPC.
//
//go:embed freecredit_localnet_issuer.pem
var localnetIssuerPEM []byte

// IssuerPayerHeader names the payer a request to the stub's issuer is for:
// the issue wire carries no payer, and the stub counts calls and fails them
// per payer so scenarios run side by side. The e2e hosts set it through the
// SDKs' header hook.
const IssuerPayerHeader = "X-Stub-Payer"

// Issuer is the localnet issuer, served on the stub node's own address. It
// signs every request, as an issuer with no gate would.
type Issuer struct {
	master ed25519.PrivateKey
	dep    ticket.DeploymentID

	mu      sync.Mutex
	signers map[freecredit.Epoch]*freecredit.DaySigner
	calls   map[string]int
}

func newIssuer(dep ticket.DeploymentID) (*Issuer, error) {
	master, err := freecredit.ParseIssuerPEM(localnetIssuerPEM)
	if err != nil {
		return nil, err
	}
	return &Issuer{master: master, dep: dep, signers: map[freecredit.Epoch]*freecredit.DaySigner{}, calls: map[string]int{}}, nil
}

// Key is the issuer's public key, as presets and node details spell it.
func (is *Issuer) Key() ed25519.PublicKey { return is.master.Public().(ed25519.PublicKey) }

// Calls is how many issue-wire requests were made for payer.
func (is *Issuer) Calls(payer solana.PublicKey) int {
	is.mu.Lock()
	defer is.mu.Unlock()
	return is.calls[payer.String()]
}

func (is *Issuer) signer(epoch freecredit.Epoch) (*freecredit.DaySigner, error) {
	is.mu.Lock()
	defer is.mu.Unlock()
	if s := is.signers[epoch]; s != nil {
		return s, nil
	}
	s, err := freecredit.NewDaySigner(nil, is.master, is.dep, epoch)
	if err != nil {
		return nil, err
	}
	is.signers[epoch] = s
	return s, nil
}

// readIssue counts the call and reads its body into v, answering a failure
// itself: false means the response is written.
func (n *Node) readIssue(w http.ResponseWriter, r *http.Request, v any) bool {
	payer := r.Header.Get(IssuerPayerHeader)
	n.issuer.mu.Lock()
	n.issuer.calls[payer]++
	n.issuer.mu.Unlock()
	if pk, err := solana.ParsePublicKey(payer); err == nil && n.behaviorFor(pk).IssuerDown {
		writeError(w, http.StatusServiceUnavailable, "issuer_down", "the stub's issuer is down for this payer")
		return false
	}
	raw, err := io.ReadAll(r.Body)
	if err == nil {
		err = json.Unmarshal(raw, v)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return false
	}
	return true
}

// issuable refuses another deployment, or an epoch the issuer doesn't sign
// for now: false means the response is written.
func (n *Node) issuable(w http.ResponseWriter, dep freecredit.Bytes, epoch freecredit.Epoch) bool {
	if string(dep) != string(n.deployment[:]) {
		writeError(w, http.StatusBadRequest, "deployment_mismatch", "another deployment")
		return false
	}
	for _, e := range freecredit.AcceptedEpochs(time.Now()) {
		if e == epoch {
			return true
		}
	}
	writeError(w, http.StatusBadRequest, freecredit.CodeEpochNotIssuable, "not an epoch this issuer signs for")
	return false
}

func (n *Node) issuerDayKey(w http.ResponseWriter, r *http.Request) {
	var req freecredit.DayKeyRequest
	if !n.readIssue(w, r, &req) || !n.issuable(w, req.Deployment, req.Epoch) {
		return
	}
	s, err := n.issuer.signer(req.Epoch)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.Key().Cert())
}

func (n *Node) issuerIssue(w http.ResponseWriter, r *http.Request) {
	var req freecredit.IssueRequest
	if !n.readIssue(w, r, &req) || !n.issuable(w, req.Deployment, req.Epoch) {
		return
	}
	if len(req.Blinded) == 0 || len(req.Blinded) > freecredit.MaxIssueBatch {
		writeError(w, http.StatusBadRequest, "bad_request", "1 to 20 blinded messages")
		return
	}
	s, err := n.issuer.signer(req.Epoch)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	resp := freecredit.IssueResponse{Signatures: make([]freecredit.Bytes, len(req.Blinded))}
	for i, b := range req.Blinded {
		if resp.Signatures[i], err = s.Sign(b); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// checkCredit verifies the credit a free reserve carries, as a node that
// trusts the localnet issuer does, and returns its spent key. The credit is
// spent only when its turn is consumed (consumeCredit), so a ticket the payer
// never uses leaves it spendable. It answers a refusal itself: false means
// the response is written.
func (n *Node) checkCredit(w http.ResponseWriter, raw json.RawMessage) (string, bool) {
	c, err := freecredit.ParseCredit(raw)
	if err == nil {
		node := freecredit.Node{Operator: n.operatorID, Node: n.nodeID}
		err = freecredit.Verify([]ed25519.PublicKey{n.issuer.Key()}, n.deployment, node, freecredit.AcceptedEpochs(time.Now()), c)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, freecredit.CodeFreeCreditInvalid, err.Error())
		return "", false
	}
	key := string(c.SpentKey())
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.spent[key] {
		writeError(w, http.StatusConflict, freecredit.CodeFreeCreditSpent, "this credit was spent here")
		return "", false
	}
	return key, true
}

// consumeCredit spends the credit e's reserve carried, refusing the turn if
// another turn spent it since. False means the response is written.
func (n *Node) consumeCredit(w http.ResponseWriter, e *entry) bool {
	if e.credit == "" {
		return true
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.spent[e.credit] {
		writeError(w, http.StatusConflict, freecredit.CodeFreeCreditSpent, "this credit was spent here")
		return false
	}
	n.spent[e.credit] = true
	n.credits[e.payer]++
	return true
}

// Credits is how many verified credits payer's free reserves carried.
func (n *Node) Credits(payer solana.PublicKey) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.credits[payer]
}

// Issuer is the stub's free-credit issuer.
func (n *Node) Issuer() *Issuer { return n.issuer }
