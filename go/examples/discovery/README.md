# discovery

Reads the fleet the way a payer does, without paying anything: every node registered
in the escrow contract, with its models, reachability, protocol and node version, and
TEE verdict, then the models a payer would route to now. It is the Go twin of the
TypeScript `discovery` example.

```bash
cd proto/go
go run ./examples/discovery                       # mainnet
go run ./examples/discovery -network testnet -direct
```

No key is needed. The chain read is a simulate sent from the network's fee sink, so on
localnet pass a funded account with `-sender` along with `-app-id`.

By default each node is probed through a relay, so no node sees this machine's IP.
`-direct` probes each node itself. `-v` logs discovery to stderr.

It builds the parts `zs.New` builds for itself: a `zs.ChainOperatorSource` and a
`zs.DynamicRegistryProvider`. A node shows as attested only when its quote verified and
both measurement checks passed (`TEEStatus.Attested`), which is the rule routing applies.
