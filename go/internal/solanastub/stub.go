/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solanastub

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/tyler-smith/go-bip39"

	"github.com/TxnLab/zerosignal/go/keystore"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

// PayerUSDC is the test USDC FundPayer gives each payer, in base units.
const PayerUSDC = 10_000_000

// SOL a run hands out. A funded payer needs fees, its USDC account's rent and
// its rent pool; the authority airdrops a localnet's free SOL generously,
// while a funder's is topped up by hand, so it gives what a run uses.
const (
	payerSOLAirdrop = 1_000_000_000
	payerSOLFunder  = 50_000_000
	// A stub's signing key pays its claims, lapses and settles, and the
	// owner its two registrations.
	signingSOL      = 500_000_000
	signingSOLFloor = 200_000_000
	ownerSOLFunder  = 100_000_000
	airdropSOL      = 2_000_000_000
)

// Stub is a stub node registered and serving on a cluster: what a scenario
// needs to fund a payer and point a Client at the node.
type Stub struct {
	Chain      *Chain
	Funding    Funding
	Node       *Node
	OperatorID uint64
	NodeID     uint64
	URL        string
	srv        *http.Server
	serveErr   chan error
}

// Options is where a stub runs and what it runs with.
type Options struct {
	// Endpoint is the cluster's JSON-RPC endpoint.
	Endpoint string
	Funding  Funding
	// Identity serves as a node already registered, at its URL. Nil
	// registers a fresh operator and node serving on Listen.
	Identity *Identity
	// Listen is the address a fresh registration serves on (host:port, port 0
	// for any).
	Listen string
}

// e2eGrace is the default grace a run with the mint's authority sets, in
// seconds: short, so the refund and lapse endings finish in minutes, and long
// enough that a settle sent as a short ticket expires still lands.
const e2eGrace = 60

// Start serves a stub node on the cluster at o.Endpoint.
//
// With the mint's authority the run lowers the Config's default grace to
// e2eGrace, so endings that wait out a deadline wait about a minute, and it
// refuses an endpoint off this machine: a localnet can be set up with devnet's
// own keys, whose deploy key is devnet's admin, and the grace change would then
// land on every devnet ticket. A funder changes nothing in the Config, so the grace is the
// cluster's.
//
// The stub serves only on loopback: its /stub/ routes fund whoever asks.
func Start(ctx context.Context, o Options) (*Stub, error) {
	if err := o.Funding.check(); err != nil {
		return nil, err
	}
	listen := o.Listen
	if o.Identity != nil {
		u, err := url.Parse(o.Identity.URL)
		if err != nil || u.Scheme != "http" || u.Port() == "" {
			return nil, fmt.Errorf("solanastub: the identity's URL %q: want http://host:port, which the stub serves", o.Identity.URL)
		}
		listen = u.Host
	} else if o.Funding.Funder != nil && checkLoopback(o.Endpoint) != nil {
		// Each fresh registration stakes the funder's USDC under an owner
		// nobody keeps, so a shared cluster's runs serve as one registered
		// once.
		return nil, errors.New("solanastub: a funder off this machine serves as a registered identity; register one with -register-node")
	}
	if err := checkLoopbackHost(listen); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	s, err := start(ctx, o, ln)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	s.srv = &http.Server{Handler: s.handler()}
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.serveErr <- err
		}
	}()
	return s, nil
}

func start(ctx context.Context, o Options, ln net.Listener) (*Stub, error) {
	s := &Stub{Funding: o.Funding, serveErr: make(chan error, 1)}
	var signing ed25519.PrivateKey
	if o.Identity == nil {
		signing = newKey()
		s.URL = "http://" + ln.Addr().String()
		var err error
		if s.Chain, s.OperatorID, s.NodeID, err = Register(ctx, o.Endpoint, o.Funding, newKey(), signing, s.URL); err != nil {
			return nil, err
		}
	} else {
		var err error
		if signing, err = o.Identity.Signing(); err != nil {
			return nil, err
		}
		if s.Chain, err = DialFunded(ctx, o.Endpoint, o.Funding); err != nil {
			return nil, err
		}
		if err := s.Chain.checkIdentity(ctx, *o.Identity, PublicKey(signing)); err != nil {
			return nil, err
		}
		if err := s.Chain.TopUpSOL(ctx, o.Funding, PublicKey(signing), signingSOLFloor, signingSOL); err != nil {
			return nil, err
		}
		s.URL, s.OperatorID, s.NodeID = o.Identity.URL, o.Identity.OperatorID, o.Identity.NodeID
	}
	var err error
	if s.Node, err = NewNode(s.Chain, signing, s.OperatorID, s.NodeID); err != nil {
		return nil, err
	}
	return s, nil
}

// DialFunded reads the cluster a run funded by f reaches. With the authority it
// refuses an endpoint off this machine and readies the Config as every run on
// it expects. Anything that spends a run's funding dials through it, since
// Dial alone has no such refusal.
func DialFunded(ctx context.Context, endpoint string, f Funding) (*Chain, error) {
	if err := f.check(); err != nil {
		return nil, err
	}
	if f.Authority != nil {
		if err := checkLoopback(endpoint); err != nil {
			return nil, err
		}
	}
	chain, err := Dial(ctx, endpoint, solana.PublicKey{})
	if err != nil {
		return nil, err
	}
	if f.Authority == nil || chain.Config.DefaultGrace == e2eGrace {
		return chain, nil
	}
	grace := uint32(e2eGrace)
	ix, err := chain.Deployment.SetConfig(PublicKey(f.Authority), zsescrow.SetConfigArgs{DefaultGrace: &grace})
	if err != nil {
		return nil, err
	}
	if _, err := chain.Send(ctx, []solana.Instruction{ix}, f.Authority); err != nil {
		return nil, err
	}
	return chain, chain.Refresh(ctx)
}

// Register registers a fresh operator, owned by owner, with one node that
// signs with signing and is reachable at baseURL, on the cluster at endpoint,
// and gives the signing key SOL for its endings. It readies the cluster as
// Start does, so a real node registered here sees what the stub sees. Only
// owner can unregister the operator and take its stake back.
func Register(ctx context.Context, endpoint string, f Funding, owner, signing ed25519.PrivateKey, baseURL string) (chain *Chain, operatorID, nodeID uint64, err error) {
	if chain, err = DialFunded(ctx, endpoint, f); err != nil {
		return nil, 0, 0, err
	}
	ownerSOL, signSOL := uint64(airdropSOL), uint64(airdropSOL)
	if f.Funder != nil {
		ownerSOL, signSOL = ownerSOLFunder, signingSOL
	}
	if err := chain.FundSOL(ctx, f, PublicKey(owner), ownerSOL); err != nil {
		return nil, 0, 0, err
	}
	if err := chain.FundSOL(ctx, f, PublicKey(signing), signSOL); err != nil {
		return nil, 0, 0, err
	}
	// The first node's stake is waived, so the operator's is all it takes.
	if err := chain.FundUSDC(ctx, f, PublicKey(owner), chain.Config.OperatorStake); err != nil {
		return nil, 0, 0, err
	}
	operatorID, nodeID, err = chain.RegisterNode(ctx, owner, PublicKey(signing), baseURL)
	if err != nil {
		return nil, 0, 0, err
	}
	return chain, operatorID, nodeID, nil
}

// Identity is a registered node's: what a run needs to serve as it again
// without registering, so a shared cluster's runs reuse one operator rather
// than stake a new one each night, and what its owner needs to unregister it
// and take the stake back.
type Identity struct {
	OperatorID uint64 `json:"operator_id"`
	NodeID     uint64 `json:"node_id"`
	URL        string `json:"url"`
	// SigningPhrase is the node's 24-word signing phrase, which zs-node reads
	// as a <NAME>_MNEMONIC; SigningAddress is its address, so a script can top
	// it up without deriving it.
	SigningPhrase  string `json:"signing_phrase"`
	SigningAddress string `json:"signing"`
	// OwnerPhrase is the operator owner's, which unregisters it.
	OwnerPhrase string `json:"owner_phrase"`
}

// NewIdentityKey is a fresh key and the 24-word phrase it comes from.
func NewIdentityKey() (ed25519.PrivateKey, string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return nil, "", err
	}
	phrase, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, "", err
	}
	key, err := keystore.SolanaKeyFromPhrase(phrase)
	return key, phrase, err
}

// Signing is the identity's signing key.
func (id Identity) Signing() (ed25519.PrivateKey, error) {
	return keystore.SolanaKeyFromPhrase(id.SigningPhrase)
}

// ReadIdentity reads an identity WriteIdentity wrote.
func ReadIdentity(path string) (Identity, error) {
	var id Identity
	raw, err := os.ReadFile(path)
	if err != nil {
		return id, err
	}
	if err := json.Unmarshal(raw, &id); err != nil {
		return id, fmt.Errorf("solanastub: identity %s: %w", path, err)
	}
	return id, nil
}

// WriteIdentity writes id to a new file only its owner reads: the phrase is
// the node's key, so an existing file is someone's and is never replaced.
func WriteIdentity(path string, id Identity) error {
	raw, err := json.Marshal(id)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// checkIdentity refuses an identity the cluster doesn't hold as written: a
// localnet reset since it was registered, another cluster's, or another
// program's (devnet's moved to its own deployment in 0.19.0).
func (ch *Chain) checkIdentity(ctx context.Context, id Identity, signing solana.PublicKey) error {
	n, err := ch.Node(ctx, id.OperatorID, id.NodeID)
	if err != nil {
		return fmt.Errorf("solanastub: the identity's node %d/%d on program %s (registered on another cluster or program?): %w",
			id.OperatorID, id.NodeID, ch.Deployment.Program, err)
	}
	if n.Signing != signing || n.BaseURL != id.URL {
		return fmt.Errorf("solanastub: node %d/%d signs with %s at %q, not the identity's %s at %q",
			id.OperatorID, id.NodeID, n.Signing, n.BaseURL, signing, id.URL)
	}
	return nil
}

// ServeErr delivers the error that stopped the server, if one does before
// Close.
func (s *Stub) ServeErr() <-chan error { return s.serveErr }

// Close stops serving.
func (s *Stub) Close() error { return s.srv.Close() }

func checkLoopback(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if err := checkLoopbackHost(u.Hostname()); err != nil {
		return fmt.Errorf("solanastub: %s is not a local validator", endpoint)
	}
	return nil
}

func checkLoopbackHost(hostport string) error {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("solanastub: %q is not on this machine", hostport)
	}
	return nil
}

// FundPayer gives payer SOL for fees and rent, and usdc base units of test
// USDC.
func (s *Stub) FundPayer(ctx context.Context, payer solana.PublicKey, usdc uint64) error {
	sol := uint64(payerSOLAirdrop)
	if s.Funding.Funder != nil {
		sol = payerSOLFunder
	}
	if err := s.Chain.FundSOL(ctx, s.Funding, payer, sol); err != nil {
		return err
	}
	return s.Chain.FundUSDC(ctx, s.Funding, payer, usdc)
}

// WithFee is what a payer pays for a charge: the program adds the protocol
// fee on top, rounded down.
func (s *Stub) WithFee(amount uint64) uint64 {
	return amount + amount*uint64(s.Chain.Config.FeeBps)/10_000
}

// Resolve settles a frozen ticket of payer's, giving the operator shareBps of
// its base price, as the protocol admin does. Only a run holding the admin
// can.
func (s *Stub) Resolve(ctx context.Context, ticketID [16]byte, payer solana.PublicKey, shareBps uint16) error {
	admin := s.Funding.Admin()
	if admin == nil {
		return ErrNoAdmin
	}
	end, err := s.Node.ending(ctx, &entry{id: ticketID, payer: payer})
	if err != nil {
		return err
	}
	end.Submitter = PublicKey(admin)
	_, err = s.Chain.Send(ctx, []solana.Instruction{s.Chain.Deployment.ResolveFrozen(end, shareBps, "solanastub")}, admin)
	return err
}

// ErrNoAdmin is Resolve on a run funded without the Config's admin.
var ErrNoAdmin = errors.New("solanastub: resolving a frozen ticket needs the Config's admin, which this run doesn't hold")

func newKey() ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}
