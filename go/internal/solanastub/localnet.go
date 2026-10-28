/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solanastub

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

// PayerUSDC is the test USDC FundPayer gives each payer, in base units.
const PayerUSDC = 10_000_000

// Localnet is a stub node registered and serving on a cluster: what a
// scenario needs to fund a payer and point a Client at the node.
type Localnet struct {
	Chain      *Chain
	Authority  ed25519.PrivateKey
	Node       *Node
	OperatorID uint64
	NodeID     uint64
	URL        string
	srv        *http.Server
	serveErr   chan error
}

// StartLocalnet registers a fresh operator and node on the cluster at
// endpoint and serves the stub for it on listen (host:port, port 0 for any).
// authority is the test USDC mint's authority, which on a localnet is also
// the Config's admin: the run lowers the Config's default grace to its
// minimum, so endings that wait out a deadline wait about a minute.
//
// It refuses an endpoint off this machine: the keypair a localnet is set up
// with is also devnet's admin, and the grace change would land on every
// devnet ticket.
func StartLocalnet(ctx context.Context, endpoint string, authority ed25519.PrivateKey, listen string) (*Localnet, error) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	signing := newKey()
	baseURL := "http://" + ln.Addr().String()
	chain, opID, nodeID, err := RegisterLocalnetNode(ctx, endpoint, authority, signing, baseURL)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	node, err := NewNode(chain, signing, opID, nodeID)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	l := &Localnet{Chain: chain, Authority: authority, Node: node, OperatorID: opID, NodeID: nodeID, URL: baseURL, serveErr: make(chan error, 1)}
	l.srv = &http.Server{Handler: l.handler()}
	go func() {
		if err := l.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			l.serveErr <- err
		}
	}()
	return l, nil
}

// RegisterLocalnetNode registers a fresh operator owning one node that signs
// with signing and is reachable at baseURL, on the cluster at endpoint, and
// gives the signing key SOL for its endings. It readies the Config as
// StartLocalnet does, so a real node registered here sees the same cluster
// as the stub, and refuses an endpoint off this machine for the same reason.
func RegisterLocalnetNode(ctx context.Context, endpoint string, authority, signing ed25519.PrivateKey, baseURL string) (chain *Chain, operatorID, nodeID uint64, err error) {
	if err := checkLoopback(endpoint); err != nil {
		return nil, 0, 0, err
	}
	if chain, err = Dial(ctx, endpoint, zsescrow.ProgramID); err != nil {
		return nil, 0, 0, err
	}
	if chain.Config.DefaultGrace != chain.Config.MinGrace {
		grace := chain.Config.MinGrace
		ix, err := chain.Deployment.SetConfig(PublicKey(authority), zsescrow.SetConfigArgs{DefaultGrace: &grace})
		if err != nil {
			return nil, 0, 0, err
		}
		if _, err := chain.Send(ctx, []solana.Instruction{ix}, authority); err != nil {
			return nil, 0, 0, err
		}
		if err := chain.Refresh(ctx); err != nil {
			return nil, 0, 0, err
		}
	}

	owner := newKey()
	for _, k := range []ed25519.PrivateKey{owner, signing} {
		if err := chain.Airdrop(ctx, PublicKey(k), 2_000_000_000); err != nil {
			return nil, 0, 0, err
		}
	}
	if err := chain.MintUSDC(ctx, authority, PublicKey(owner), chain.Config.OperatorStake+chain.Config.NodeStake); err != nil {
		return nil, 0, 0, err
	}
	operatorID, nodeID, err = chain.RegisterNode(ctx, owner, PublicKey(signing), baseURL)
	if err != nil {
		return nil, 0, 0, err
	}
	return chain, operatorID, nodeID, nil
}

// ServeErr delivers the error that stopped the server, if one does before
// Close.
func (l *Localnet) ServeErr() <-chan error { return l.serveErr }

// Close stops serving.
func (l *Localnet) Close() error { return l.srv.Close() }

func checkLoopback(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("solanastub: %s is not a local validator", endpoint)
	}
	return nil
}

// FundPayer gives payer a SOL for fees and rent and PayerUSDC of test USDC.
func (l *Localnet) FundPayer(ctx context.Context, payer solana.PublicKey) error {
	if err := l.Chain.Airdrop(ctx, payer, 1_000_000_000); err != nil {
		return err
	}
	return l.Chain.MintUSDC(ctx, l.Authority, payer, PayerUSDC)
}

// WithFee is what a payer pays for a charge: the program adds the protocol
// fee on top, rounded down.
func (l *Localnet) WithFee(amount uint64) uint64 {
	return amount + amount*uint64(l.Chain.Config.FeeBps)/10_000
}

func newKey() ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}
