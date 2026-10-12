# discovery

Lists the network's nodes and the models a payer could route to, the way the SDK's router sees
them. Nothing is paid and no key is needed. It reads the escrow's operator and node records from
chain, probes each node once (through a relay, so no node sees your address), checks TEE evidence,
and prints:

- one row per node, with its reachability (`ok`, `probing`, `failing`, `incompatible`), wire
  version, TEE verdict, staging flag, model count and URL;
- the merged model list that `/v1/models` would serve.

```bash
cd proto && pnpm install && make build-sdk
cd examples/discovery
pnpm start                     # mainnet
pnpm start --network testnet
```

The catalog is saved to `./catalog.json` (`--catalog` to move it) through a small file-backed
`StorageAdapter`, so the next run starts from the nodes this one saw.

A `Client` builds the same `ChainOperatorSource` and `DiscoveryRegistry` itself when its `Config`
has no `registry`. Build them yourself, as here, to show a catalog before the user has a key, or to
share one registry between several Clients (`buildDiscovery` in the SDK README).
