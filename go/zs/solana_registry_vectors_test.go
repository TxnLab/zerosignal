/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/solana_registry_vectors.json: the
// zs_escrow program's Operator and Node accounts, as a getProgramAccounts
// answer, to the operators SolanaChainReader builds, through the RPC client
// against a fake RPC, and the signer-balance pass ChainOperatorSource runs
// over it. Every account starts from the program's own fixtures
// (solana_account_vectors.json); the edited ones are re-encoded here, after
// this test's encoder is checked against those fixtures. want uses the field
// names of operator_vectors.json's chain_nodes, so a node reads the same on
// either rail. The TS SDK's SolanaChainReader (sdk/src/registry/solana.ts)
// replays it.
//
//	cd proto/go && go test ./zs -run TestSolanaRegistryVectors -update

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

const (
	solanaRegistryVectorsPath = "../../testdata/solana_registry_vectors.json"
	solanaAccountFixturesPath = "../../testdata/solana_account_vectors.json"
)

// solanaRegistryAccount is one entry of a getProgramAccounts answer.
type solanaRegistryAccount struct {
	Pubkey     string `json:"pubkey"`
	Owner      string `json:"owner"`
	Lamports   uint64 `json:"lamports"`
	DataBase64 string `json:"data_base64"`
}

// solanaRegistrySkip is an account the read left out, and why: "evicted" (a
// node of an evicted operator), "base_url" (resolveSolanaNode refused it),
// "foreign_owner" (an account the program does not own), "no_operator" (a
// node whose operator has no account), "unrequested" (a node of an operator
// OperatorIDs leaves out).
type solanaRegistrySkip struct {
	Account string `json:"account"`
	Reason  string `json:"reason"`
}

// solanaRegistryCase is one read: the two getProgramAccounts answers, on
// CurrentDay (Unix seconds / 86400), with OperatorIDs as the restriction.
// Want is the operators, in order; Error is "" or "no_operators" (the empty
// fleet the doctor reports), "operator_not_found" or "account_version" (an
// account a later program wrote), in which case Want and Skipped are empty.
// Skipped is sorted by account.
type solanaRegistryCase struct {
	Name        string                  `json:"name"`
	CurrentDay  uint64                  `json:"current_day"`
	OperatorIDs []uint64                `json:"operator_ids,omitempty"`
	Operators   []solanaRegistryAccount `json:"operators"`
	Nodes       []solanaRegistryAccount `json:"nodes"`
	Want        []chainNodeVector       `json:"want"`
	Skipped     []solanaRegistrySkip    `json:"skipped"`
	Error       string                  `json:"error"`
}

// solanaSignerBalance is one signer's getBalance answer: Lamports, or an RPC
// error when it is null.
type solanaSignerBalance struct {
	SigningAddr string  `json:"signing_addr"`
	Lamports    *uint64 `json:"lamports"`
}

// solanaSignerWant is a node's reading after a pass, and whether the shared
// selection rule holds it out.
type solanaSignerWant struct {
	OperatorID              uint64  `json:"operator_id"`
	NodeID                  uint64  `json:"node_id"`
	SigningAddr             string  `json:"signing_addr"`
	SignerSpendableLamports *uint64 `json:"signer_spendable_lamports"`
	Underfunded             bool    `json:"underfunded"`
}

// solanaSignerPass is one FetchChain: the balances the RPC answers, the
// getBalance params the pass sent, sorted, and the nodes it built.
type solanaSignerPass struct {
	Balances []solanaSignerBalance `json:"balances"`
	Sent     []json.RawMessage     `json:"sent"`
	Want     []solanaSignerWant    `json:"want"`
}

// solanaSignerCase is a run of passes by one ChainOperatorSource over the
// block's operators and the case's nodes, so a pass can read what an earlier
// one left.
type solanaSignerCase struct {
	Name   string                  `json:"name"`
	Nodes  []solanaRegistryAccount `json:"nodes"`
	Passes []solanaSignerPass      `json:"passes"`
}

// solanaFixtureAccount is the part of a solana_account_vectors.json account
// this test reads.
type solanaFixtureAccount struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Address    string `json:"address"`
	Owner      string `json:"owner"`
	Lamports   string `json:"lamports"`
	DataBase64 string `json:"data_base64"`
}

type solanaAccountFixtures struct {
	ProgramID string                 `json:"program_id"`
	Accounts  []solanaFixtureAccount `json:"accounts"`
	Context   struct {
		GenesisHash string `json:"genesis_hash"`
		Keys        map[string]struct {
			Pubkey string `json:"pubkey"`
		} `json:"keys"`
	} `json:"context"`
}

// fakeSolanaRPC answers getGenesisHash, getBlockHeight, the rent quote and
// the two getProgramAccounts reads, telling those apart by the discriminator
// they filter on, and keeps the params each read sent. It answers getBalance
// from balances, with an RPC error for an address it has no lamports for, and
// keeps each one's params.
type fakeSolanaRPC struct {
	genesis   solana.Hash
	operators []solanaRegistryAccount
	nodes     []solanaRegistryAccount

	// accounts answers getAccountInfo by address; one it lacks has no account.
	accounts map[string]solanaRegistryAccount

	mu            sync.Mutex
	opParams      json.RawMessage
	nodeParams    json.RawMessage
	balances      map[string]*uint64
	balanceParams []json.RawMessage
}

// solanaRPCError is a JSON-RPC error neither client retries (invalid params),
// so an unreadable balance fails its read at once.
const solanaRPCError = -32602

func (f *fakeSolanaRPC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     uint64            `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var result any
	switch req.Method {
	case "getGenesisHash":
		result = f.genesis.String()
	case "getBlockHeight":
		result = 1_000
	case "getMinimumBalanceForRentExemption":
		var n uint64
		if len(req.Params) == 0 || json.Unmarshal(req.Params[0], &n) != nil {
			http.Error(w, "unexpected getMinimumBalanceForRentExemption params", http.StatusBadRequest)
			return
		}
		result = (128 + n) * 6_960
	case "getAccountInfo":
		var addr string
		if len(req.Params) == 0 || json.Unmarshal(req.Params[0], &addr) != nil {
			http.Error(w, "unexpected getAccountInfo params", http.StatusBadRequest)
			return
		}
		var value any
		if a, ok := f.accounts[addr]; ok {
			value = map[string]any{
				"data": []string{a.DataBase64, "base64"}, "executable": false,
				"lamports": a.Lamports, "owner": a.Owner, "rentEpoch": 0, "space": len(a.DataBase64) * 3 / 4,
			}
		}
		result = map[string]any{"context": map[string]any{"slot": 1}, "value": value}
	case "getBalance":
		var addr string
		if len(req.Params) == 0 || json.Unmarshal(req.Params[0], &addr) != nil {
			http.Error(w, "unexpected getBalance params", http.StatusBadRequest)
			return
		}
		params, _ := json.Marshal(req.Params)
		f.mu.Lock()
		f.balanceParams = append(f.balanceParams, params)
		lamports := f.balances[addr]
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if lamports == nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]any{"code": solanaRPCError, "message": "unreadable"}})
			return
		}
		result = map[string]any{"context": map[string]any{"slot": 1}, "value": *lamports}
	case "getProgramAccounts":
		var cfg struct {
			Filters []struct {
				Memcmp *struct {
					Bytes string `json:"bytes"`
				} `json:"memcmp"`
			} `json:"filters"`
		}
		if len(req.Params) != 2 || json.Unmarshal(req.Params[1], &cfg) != nil || len(cfg.Filters) == 0 || cfg.Filters[0].Memcmp == nil {
			http.Error(w, "unexpected getProgramAccounts params", http.StatusBadRequest)
			return
		}
		params, _ := json.Marshal(req.Params)
		opDisc, nodeDisc := zsescrow.AccountDiscriminator("Operator"), zsescrow.AccountDiscriminator("Node")
		var accts []solanaRegistryAccount
		f.mu.Lock()
		switch cfg.Filters[0].Memcmp.Bytes {
		case base64.StdEncoding.EncodeToString(opDisc[:]):
			accts, f.opParams = f.operators, params
		case base64.StdEncoding.EncodeToString(nodeDisc[:]):
			accts, f.nodeParams = f.nodes, params
		}
		f.mu.Unlock()
		list := []map[string]any{}
		for _, a := range accts {
			list = append(list, map[string]any{
				"pubkey": a.Pubkey,
				"account": map[string]any{
					"data": []string{a.DataBase64, "base64"}, "executable": false,
					"lamports": a.Lamports, "owner": a.Owner, "rentEpoch": 0, "space": len(a.DataBase64) * 3 / 4,
				},
			})
		}
		result = list
	default:
		http.Error(w, "unexpected method "+req.Method, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
}

// encodeSolanaOperator writes an Operator account in the program's layout
// (zsescrow.DecodeOperator's order).
func encodeSolanaOperator(o *zsescrow.Operator) []byte {
	d := zsescrow.AccountDiscriminator("Operator")
	b := append(d[:], o.Version, byte(o.Status), o.Bump)
	for _, v := range []uint64{o.ID, o.NextNodeID, o.LiveNodeCount, o.Stake} {
		b = binary.LittleEndian.AppendUint64(b, v)
	}
	b = append(b, o.Owner[:]...)
	b = append(b, o.NameRef[:]...)
	return append(b, o.Reserve[:]...)
}

// encodeSolanaNode writes a Node account in the program's layout
// (zsescrow.DecodeNode's order), with base_url_len from BaseURL.
func encodeSolanaNode(n *zsescrow.Node) []byte {
	d := zsescrow.AccountDiscriminator("Node")
	b := append(d[:], n.Version, n.Status, n.Staging, n.Bump, n.VaultBump, byte(len(n.BaseURL)))
	b = append(b, n.Pad0[:]...)
	b = append(b, n.Signing[:]...)
	b = append(b, n.Vault[:]...)
	b = append(b, n.Operator[:]...)
	url := make([]byte, zsescrow.BaseURLMax)
	copy(url, n.BaseURL)
	b = append(b, url...)
	u64 := func(vs ...uint64) {
		for _, v := range vs {
			b = binary.LittleEndian.AppendUint64(b, v)
		}
	}
	u64(n.OperatorID, n.NodeID, n.Stake, n.AccruedPay, n.AccruedFee, n.LiveTickets, n.OpensTotal, uint64(n.LastActivityAt))
	u64(n.SettledCount, n.LapsedCount, n.RefundedCount, n.RefundedTotal, n.LatencyTotalMs, n.LatencySamples)
	u64(n.TTFTEwmaMs, n.DecodeTPSEwma, n.RevenueTotal, n.InputUnitsTotal)
	u64(n.OutputUnits[:]...)
	u64(uint64(n.RingDay))
	u64(n.RingRevenue[:]...)
	u64(n.ProtestedCount, n.ProtestedTotal, n.FrozenDisputeCount, n.FrozenDisputeTotal, n.ResolvedCount, n.ResolvedTotal)
	return append(b, n.Reserve[:]...)
}

func TestSolanaRegistryVectors(t *testing.T) {
	raw, err := os.ReadFile(solanaAccountFixturesPath)
	if err != nil {
		t.Fatal(err)
	}
	var fx solanaAccountFixtures
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	program := solana.MustPublicKey(fx.ProgramID)
	dep := zsescrow.Deployment{Program: program}
	genesisBytes, err := hex.DecodeString(fx.Context.GenesisHash)
	if err != nil || len(genesisBytes) != 32 {
		t.Fatalf("fixture genesis hash: %v", err)
	}
	genesis := solana.Hash(genesisBytes)

	fixture := func(name string) solanaFixtureAccount {
		for _, a := range fx.Accounts {
			if a.Name == name {
				return a
			}
		}
		t.Fatalf("fixture %s missing", name)
		return solanaFixtureAccount{}
	}
	account := func(f solanaFixtureAccount) solanaRegistryAccount {
		lamports, err := strconv.ParseUint(f.Lamports, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return solanaRegistryAccount{Pubkey: f.Address, Owner: f.Owner, Lamports: lamports, DataBase64: f.DataBase64}
	}
	// decoded reads a fixture with the decoder under test and checks this
	// test's encoder writes the same bytes back, so an edited account differs
	// from the program's only where its case says.
	decodedOperator := func(name string) *zsescrow.Operator {
		f := fixture(name)
		data, _ := base64.StdEncoding.DecodeString(f.DataBase64)
		o, err := zsescrow.DecodeOperator(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(encodeSolanaOperator(o), data) {
			t.Fatalf("%s: the test encoder does not write the program's bytes", name)
		}
		return o
	}
	decodedNode := func(name string) *zsescrow.Node {
		f := fixture(name)
		data, _ := base64.StdEncoding.DecodeString(f.DataBase64)
		n, err := zsescrow.DecodeNode(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(encodeSolanaNode(n), data) {
			t.Fatalf("%s: the test encoder does not write the program's bytes", name)
		}
		return n
	}
	opAccount := func(name string, edit func(*zsescrow.Operator)) solanaRegistryAccount {
		a := account(fixture(name))
		o := decodedOperator(name)
		edit(o)
		a.Pubkey = dep.Operator(o.ID).String()
		a.DataBase64 = base64.StdEncoding.EncodeToString(encodeSolanaOperator(o))
		return a
	}
	nodeAccount := func(name string, edit func(*zsescrow.Node)) solanaRegistryAccount {
		a := account(fixture(name))
		n := decodedNode(name)
		edit(n)
		a.Pubkey = dep.Node(n.OperatorID, n.NodeID).String()
		a.DataBase64 = base64.StdEncoding.EncodeToString(encodeSolanaNode(n))
		return a
	}
	rehome := func(opID, nodeID uint64) func(*zsescrow.Node) {
		return func(n *zsescrow.Node) {
			n.OperatorID, n.NodeID, n.Operator = opID, nodeID, dep.Operator(opID)
		}
	}

	named, evicted := account(fixture("operator_named")), account(fixture("operator_evicted"))
	node1, node2 := account(fixture("node_with_metrics")), account(fixture("node_staging_rotated"))
	ringDay := uint64(decodedNode("node_with_metrics").RingDay)
	operator3 := opAccount("operator_named", func(o *zsescrow.Operator) {
		o.ID = 3
		o.Owner = solana.MustPublicKey(fx.Context.Keys["owner2"].Pubkey)
	})
	node31 := nodeAccount("node_staging_rotated", rehome(3, 1))

	var cases []solanaRegistryCase
	add := func(name string, day uint64, ops, nodes []solanaRegistryAccount, ids ...uint64) {
		cases = append(cases, solanaRegistryCase{Name: name, CurrentDay: day, OperatorIDs: ids, Operators: ops, Nodes: nodes})
	}
	fleet := []solanaRegistryAccount{named, evicted}

	add("the program's fixtures", ringDay, fleet, []solanaRegistryAccount{node1, node2})
	add("revenue windows end days after the ring's last write", ringDay+6, fleet, []solanaRegistryAccount{node1})
	add("a ring thirty days old reads as no revenue", ringDay+30, fleet, []solanaRegistryAccount{node1})
	add("a clock behind the ring reads no revenue", ringDay-1, fleet, []solanaRegistryAccount{node1})
	add("an evicted operator's nodes are left out", ringDay, fleet, []solanaRegistryAccount{node2, nodeAccount("node_with_metrics", rehome(2, 1))})
	add("an operator status a later program adds still routes", ringDay,
		[]solanaRegistryAccount{opAccount("operator_named", func(o *zsescrow.Operator) { o.Status = 2 })}, []solanaRegistryAccount{node1})
	add("the node status byte is not read", ringDay, fleet,
		[]solanaRegistryAccount{nodeAccount("node_with_metrics", func(n *zsescrow.Node) { n.Status = 0 })})
	add("any non-zero staging byte is staging", ringDay, fleet,
		[]solanaRegistryAccount{nodeAccount("node_with_metrics", func(n *zsescrow.Node) { n.Staging = 7 })})
	add("trailing zero padding and slashes are trimmed from the base URL", ringDay, fleet,
		[]solanaRegistryAccount{nodeAccount("node_with_metrics", func(n *zsescrow.Node) { n.BaseURL = "https://node-1.example.net/zs//\x00\x00" })})
	add("a base URL with no scheme is skipped", ringDay, fleet, []solanaRegistryAccount{
		nodeAccount("node_with_metrics", func(n *zsescrow.Node) { n.BaseURL = "node-1.example.net" }), node2,
	})
	add("an uppercase scheme is skipped", ringDay, fleet,
		[]solanaRegistryAccount{nodeAccount("node_with_metrics", func(n *zsescrow.Node) { n.BaseURL = "HTTPS://node-1.example.net" })})
	add("a later program's node account fails the read", ringDay, fleet, []solanaRegistryAccount{
		nodeAccount("node_with_metrics", func(n *zsescrow.Node) { n.Version = zsescrow.AccountVersion + 1 }), node2,
	})
	add("a later program's operator account fails the read", ringDay, []solanaRegistryAccount{
		opAccount("operator_named", func(o *zsescrow.Operator) { o.Version = zsescrow.AccountVersion + 1 }), evicted,
	}, []solanaRegistryAccount{node1, node2})
	foreign := node1
	foreign.Owner = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	add("an account the program does not own is skipped", ringDay, fleet, []solanaRegistryAccount{foreign, node2})
	// An operator account under another program, naming a real operator's id
	// with another owner: read after the real one, it would replace it.
	foreignOp := opAccount("operator_named", func(o *zsescrow.Operator) {
		o.Owner = solana.MustPublicKey(fx.Context.Keys["owner2"].Pubkey)
	})
	foreignOp.Pubkey = fx.Context.Keys["owner2"].Pubkey
	foreignOp.Owner = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	add("an operator account the program does not own is skipped", ringDay,
		[]solanaRegistryAccount{named, evicted, foreignOp}, []solanaRegistryAccount{node1})
	add("an operator account the program does not own is no fleet", ringDay,
		[]solanaRegistryAccount{foreignOp}, []solanaRegistryAccount{node1})
	add("no operator accounts is an empty fleet", ringDay, []solanaRegistryAccount{}, []solanaRegistryAccount{node1})
	add("an evicted operator alone is a fleet with no nodes", ringDay, []solanaRegistryAccount{evicted}, []solanaRegistryAccount{})
	add("operator ids restrict the read", ringDay, []solanaRegistryAccount{named, evicted, operator3},
		[]solanaRegistryAccount{node1, node2, node31}, 3)
	add("a requested operator not on chain fails the read", ringDay, fleet, []solanaRegistryAccount{node1}, 1, 9)
	add("nodes are sorted by operator then node", ringDay, []solanaRegistryAccount{operator3, evicted, named},
		[]solanaRegistryAccount{node31, node2, node1})
	add("a node whose operator has no account is left out", ringDay, fleet,
		[]solanaRegistryAccount{nodeAccount("node_with_metrics", rehome(7, 1)), node2})
	add("a negative activity time and ring day read as never", ringDay, fleet,
		[]solanaRegistryAccount{nodeAccount("node_with_metrics", func(n *zsescrow.Node) { n.LastActivityAt, n.RingDay = -5, -1 })})

	fake := &fakeSolanaRPC{genesis: genesis}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	client, err := rpc.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	for i := range cases {
		runSolanaRegistryCase(t, &cases[i], fake, client, program)
	}

	signer1, signer2 := decodedNode("node_with_metrics").Signing.String(), decodedNode("node_staging_rotated").Signing.String()
	floor, reserve := selection.MinSignerSpendableLamports, solanaSignerReserveLamports
	lamports := func(v uint64) *uint64 { return &v }
	const funded = 1_000_000_000
	balances := func(b1, b2 *uint64) []solanaSignerBalance {
		return []solanaSignerBalance{{signer1, b1}, {signer2, b2}}
	}
	twoNodes := []solanaRegistryAccount{node1, node2}
	pass := func(b []solanaSignerBalance) solanaSignerPass { return solanaSignerPass{Balances: b} }
	signerCases := []solanaSignerCase{
		{Name: "funded signers route", Nodes: twoNodes,
			Passes: []solanaSignerPass{pass(balances(lamports(funded), lamports(funded)))}},
		{Name: "a signer exactly at the floor above its reserve routes", Nodes: twoNodes,
			Passes: []solanaSignerPass{pass(balances(lamports(floor+reserve), lamports(funded)))}},
		{Name: "a signer one lamport below the floor is held out", Nodes: twoNodes,
			Passes: []solanaSignerPass{pass(balances(lamports(floor+reserve-1), lamports(funded)))}},
		{Name: "a signer below its own reserve, or with no account, has nothing spendable", Nodes: twoNodes,
			Passes: []solanaSignerPass{pass(balances(lamports(reserve-1), lamports(0)))}},
		{Name: "a balance never read routes", Nodes: twoNodes,
			Passes: []solanaSignerPass{pass(balances(nil, lamports(floor+reserve-1)))}},
		{Name: "an unreadable balance keeps the last reading until a read shows a top-up", Nodes: twoNodes,
			Passes: []solanaSignerPass{
				pass(balances(lamports(floor+reserve-1), lamports(floor+reserve))),
				pass(balances(nil, nil)),
				pass(balances(lamports(funded), nil)),
			}},
		{Name: "a signer two nodes share is read once", Nodes: []solanaRegistryAccount{
			node1, nodeAccount("node_staging_rotated", func(n *zsescrow.Node) { n.Signing = solana.MustPublicKey(signer1) }),
		}, Passes: []solanaSignerPass{pass([]solanaSignerBalance{{signer1, lamports(floor + reserve - 1)}})}},
	}
	for i := range signerCases {
		runSolanaSignerCase(t, &signerCases[i], fleet, fake, client, program)
	}

	reader := &SolanaChainReader{RPC: client, Program: program}
	d, err := reader.ReadDeployment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	type signerBalanceBlock struct {
		Comment                    string                  `json:"comment"`
		MinSignerSpendableLamports uint64                  `json:"min_signer_spendable_lamports"`
		SignerReserveLamports      uint64                  `json:"signer_reserve_lamports"`
		Operators                  []solanaRegistryAccount `json:"operators"`
		Cases                      []solanaSignerCase      `json:"cases"`
	}
	f := struct {
		Comment        string               `json:"comment"`
		ProgramID      string               `json:"program_id"`
		GenesisHash    string               `json:"genesis_hash"`
		DeploymentHex  string               `json:"deployment_hex"`
		OperatorParams json.RawMessage      `json:"operator_params"`
		NodeParams     json.RawMessage      `json:"node_params"`
		Cases          []solanaRegistryCase `json:"cases"`
		SignerBalance  signerBalanceBlock   `json:"signer_balance"`
	}{
		Comment: "Generated by proto/go/zs TestSolanaRegistryVectors from the accounts in solana_account_vectors.json. " +
			"genesis_hash is what getGenesisHash answers and deployment_hex the deployment id read from it; operator_params and node_params are the getProgramAccounts params each read sends. " +
			"Each case's want, skipped and error are compared exactly, skipped as sorted by account.",
		ProgramID:      program.String(),
		GenesisHash:    genesis.String(),
		DeploymentHex:  hex.EncodeToString(d[:]),
		OperatorParams: fake.opParams,
		NodeParams:     fake.nodeParams,
		Cases:          cases,
		SignerBalance: signerBalanceBlock{
			Comment: "ChainOperatorSource over SolanaChainReader, one source per case and one FetchChain per pass, over operators and the case's nodes. " +
				"balances are getBalance's answers (null: an RPC error); sent is the getBalance params the pass sent, sorted; want is each node's signer_spendable_lamports " +
				"(null: never read) and whether the shared selection rule holds it out. min_signer_spendable_lamports is that rule's floor and signer_reserve_lamports " +
				"what a reading leaves out of the balance.",
			MinSignerSpendableLamports: floor,
			SignerReserveLamports:      reserve,
			Operators:                  fleet,
			Cases:                      signerCases,
		},
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	if *updateVectors {
		if err := os.WriteFile(solanaRegistryVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(solanaRegistryVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("Solana registry read differs from %s; if the change is intended, regenerate with -update and review the diff", solanaRegistryVectorsPath)
	}
}

// runSolanaRegistryCase runs ReadChain over the case's accounts and records
// what it built, and why each account it left out was left out: from its log
// lines where it logs one, else from the account's operator.
func runSolanaRegistryCase(t *testing.T, sc *solanaRegistryCase, fake *fakeSolanaRPC, client rpc.Client, program solana.PublicKey) {
	fake.mu.Lock()
	fake.operators, fake.nodes = sc.Operators, sc.Nodes
	fake.mu.Unlock()
	var logged bytes.Buffer
	// Late in the day, so a clock read wrong by hours lands on the next one.
	at := time.Unix(int64(sc.CurrentDay)*escrow.SecondsPerDay+escrow.SecondsPerDay-1, 0)
	r := &SolanaChainReader{
		RPC: client, Program: program, OperatorIDs: sc.OperatorIDs,
		Log:   slog.New(slog.NewJSONHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn})),
		clock: func() time.Time { return at },
	}
	ops, err := r.ReadChain(context.Background())
	sc.Want, sc.Skipped = []chainNodeVector{}, []solanaRegistrySkip{}
	switch {
	case err == nil:
	case errors.Is(err, errNoOperators):
		sc.Error = "no_operators"
		return
	case strings.Contains(err.Error(), "not found on chain"):
		sc.Error = "operator_not_found"
		return
	case errors.Is(err, zsescrow.ErrVersion):
		sc.Error = "account_version"
		return
	default:
		t.Fatalf("%s: ReadChain: %v", sc.Name, err)
	}
	for _, o := range ops {
		sc.Want = append(sc.Want, chainNodeVectorOf(o))
	}

	type ids struct{ op, node uint64 }
	keyOf := map[ids]string{}
	skipped := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSpace(logged.String()), "\n") {
		if line == "" {
			continue
		}
		var l struct {
			Msg        string `json:"msg"`
			Account    string `json:"account"`
			OperatorID uint64 `json:"operator_id"`
			NodeID     uint64 `json:"node_id"`
			Err        string `json:"err"`
		}
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			t.Fatalf("%s: log line %q: %v", sc.Name, line, err)
		}
		switch l.Msg {
		case "skipping registry account the program does not own":
			sc.Skipped = append(sc.Skipped, solanaRegistrySkip{l.Account, "foreign_owner"})
		case "skipping unparseable node record":
			if !strings.Contains(l.Err, "base_url") {
				t.Fatalf("%s: node skipped for no reason this vector names: %s", sc.Name, line)
			}
			// Filled in below, once the node accounts are decoded.
			keyOf[ids{l.OperatorID, l.NodeID}] = "base_url"
		default:
			t.Fatalf("%s: unexpected log line %s", sc.Name, line)
		}
	}
	for _, s := range sc.Skipped {
		skipped[s.Account] = true
	}

	operators := map[uint64]*zsescrow.Operator{}
	for _, a := range sc.Operators {
		if skipped[a.Pubkey] {
			continue
		}
		data, _ := base64.StdEncoding.DecodeString(a.DataBase64)
		o, err := zsescrow.DecodeOperator(data)
		if err != nil {
			t.Fatalf("%s: operator %s: %v", sc.Name, a.Pubkey, err)
		}
		operators[o.ID] = o
	}
	built := map[ids]bool{}
	for _, o := range ops {
		built[ids{o.ID, o.NodeID}] = true
	}
	for _, a := range sc.Nodes {
		if skipped[a.Pubkey] {
			continue
		}
		data, _ := base64.StdEncoding.DecodeString(a.DataBase64)
		n, err := zsescrow.DecodeNode(data)
		if err != nil {
			t.Fatalf("%s: node %s: %v", sc.Name, a.Pubkey, err)
		}
		id := ids{n.OperatorID, n.NodeID}
		op, known := operators[n.OperatorID]
		var reason string
		switch {
		case built[id]:
			continue
		case keyOf[id] != "":
			reason = keyOf[id]
		case !known:
			reason = "no_operator"
		case len(sc.OperatorIDs) > 0 && !slices.Contains(sc.OperatorIDs, n.OperatorID):
			reason = "unrequested"
		case op.Status == zsescrow.OperatorStatusEvicted:
			reason = "evicted"
		default:
			t.Fatalf("%s: node %s left out for no reason this vector names", sc.Name, a.Pubkey)
		}
		sc.Skipped = append(sc.Skipped, solanaRegistrySkip{a.Pubkey, reason})
	}
	slices.SortFunc(sc.Skipped, func(a, b solanaRegistrySkip) int { return strings.Compare(a.Account, b.Account) })
}

// runSolanaSignerCase runs the case's passes through one ChainOperatorSource
// and records, for each, what it sent and the readings and verdicts it built.
func runSolanaSignerCase(t *testing.T, sc *solanaSignerCase, operators []solanaRegistryAccount, fake *fakeSolanaRPC, client rpc.Client, program solana.PublicKey) {
	s := &ChainOperatorSource{
		Chain: &SolanaChainReader{RPC: client, Program: program},
		Log:   slog.New(slog.DiscardHandler),
	}
	for i := range sc.Passes {
		p := &sc.Passes[i]
		fake.mu.Lock()
		fake.operators, fake.nodes, fake.balanceParams = operators, sc.Nodes, nil
		fake.balances = map[string]*uint64{}
		for _, b := range p.Balances {
			fake.balances[b.SigningAddr] = b.Lamports
		}
		fake.mu.Unlock()
		ops, err := s.FetchChain(context.Background())
		if err != nil {
			t.Fatalf("%s: pass %d: FetchChain: %v", sc.Name, i, err)
		}
		fake.mu.Lock()
		p.Sent = slices.Clone(fake.balanceParams)
		fake.mu.Unlock()
		slices.SortFunc(p.Sent, func(a, b json.RawMessage) int { return bytes.Compare(a, b) })
		p.Want = []solanaSignerWant{}
		for _, o := range ops {
			if o.SignerSpendableMicroAlgos != nil {
				t.Fatalf("%s: pass %d: a Solana node read a microAlgo balance", sc.Name, i)
			}
			p.Want = append(p.Want, solanaSignerWant{
				OperatorID: o.ID, NodeID: o.NodeID, SigningAddr: o.SigningAddr,
				SignerSpendableLamports: o.SignerSpendableLamports, Underfunded: o.Selection().SignerUnderfunded(),
			})
		}
	}
}

func chainNodeVectorOf(o Operator) chainNodeVector {
	m := o.Metrics
	return chainNodeVector{
		ID: o.ID, NodeID: o.NodeID, NFDAppID: o.NFDAppID, OwnerAddr: o.OwnerAddr, SigningAddr: o.SigningAddr,
		TicketSigningKeyHex: hex.EncodeToString(o.TicketSigningKey), BaseURL: o.BaseURL, Staging: o.Staging,
		Metrics: chainMetricsVector{
			LatencyEwmaMs: m.LatencyEwmaMs, TokensPerSecEwma: m.TokensPerSecEwma, LastActivityAt: m.LastActivityAt,
			TicketsOpened: m.TicketsOpened, TicketsSettled: m.TicketsSettled, TicketsLapsedSettled: m.TicketsLapsedSettled,
			TicketsRefundedInactive: m.TicketsRefundedInactive, TicketsProtested: m.TicketsProtested,
			TicketsFrozenDispute: m.TicketsFrozenDispute, TotalRefundedInactiveUsdc: m.TotalRefundedInactiveUsdc,
			TotalProtestedUsdc: m.TotalProtestedUsdc, TotalFrozenDisputeUsdc: m.TotalFrozenDisputeUsdc,
			LatencyTotalMs: m.LatencyTotalMs, LatencySamples: m.LatencySamples, TotalRevenueGross: m.TotalRevenueGross,
			Revenue24hUsdc: m.Revenue24hUsdc, Revenue7dUsdc: m.Revenue7dUsdc, Revenue30dUsdc: m.Revenue30dUsdc,
		},
	}
}
