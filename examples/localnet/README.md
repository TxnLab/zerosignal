# localnet

Runs one turn against a ZeroSignal stack on your own machine, with no real money involved. The
code is ordinary; the point is the four `Config` settings that differ from a public network:

| Setting | Why |
|---|---|
| `network: { network: 'localnet', escrowAppId }` | The localnet preset is AlgoKit's algod at `localhost:4001`. It has no escrow app built in, so you name the one you deployed. |
| `allowPrivateHosts: true` | The node is on `localhost`. The SDK's default fetch refuses to dial a private address on any network, since any operator can register any URL. |
| `privacy: 'direct'` | A relay is another node. With a single node there is none, and the default, `relay_required`, would send nothing. |
| `allowStaging: true` | A node registered for testing is often marked staging, and routing leaves staging nodes out by default. |

All four are for development only.

## The stack

1. `algokit localnet start`.
2. Deploy the escrow contract to localnet. Its bootstrap mints a local USDC asset and prints the app
   id.
3. Register an operator and a node against that app, and run `zs-node` on this machine with an
   upstream model behind it (see the zs-node operator guide).
4. Fund a payer account with ALGO from the localnet dispenser (`algokit dispenser` or the KMD
   default wallet), opt it into the local USDC asset, and send it some.

## Run

```bash
cd proto && pnpm install && make build-sdk
cd examples/localnet
ZS_ESCROW_APP_ID=<app id> ZS_MNEMONIC="word word …" pnpm start --model <model id> "hello"
```

The example lists the nodes the SDK found, then prints the answer. Its logger shows each step:
discovery, reserve, escrow open and settle.
