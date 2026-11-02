# localnet

Runs one turn against a ZeroSignal stack on your own machine, with no real money involved. The
code is ordinary; the one `Config` setting that differs from a public network is the network:

| Setting | Why |
|---|---|
| `network: { network: 'localnet', escrowAppId }` | The localnet preset is AlgoKit's algod at `localhost:4001`. It has no escrow app built in, so you name the one you deployed. |

On a local chain (`isLocal`: the localnet preset at a loopback endpoint) the SDK also sends
direct and lets the default fetch reach a node on `localhost`, since the one node there has no
relay owned by someone else and is on this machine. Elsewhere both stay off unless set.

## The stack

[`LOCALNET.md`](../../LOCALNET.md) walks through each step, on either rail.

1. `algokit localnet start`.
2. Deploy the escrow contract to localnet. Its bootstrap mints a local USDC asset and prints the app
   id.
3. Register an operator and a node against that app, and run `zs-node` on this machine with an
   upstream model behind it (see the zs-node operator guide).
4. Fund a payer account with ALGO and the local USDC from an account in the KMD default wallet,
   which holds localnet's ALGO and, with bootstrap's defaults, all its USDC
   (`algokit goal clerk send`, `algokit goal asset send`), after opting it into the USDC asset.

## Run

```bash
cd proto && pnpm install && make build-sdk
cd examples/localnet
ZS_ESCROW_APP_ID=<app id> ZS_MNEMONIC="word word …" pnpm start --model <model id> "hello"
```

The example lists the nodes the SDK found, then prints the answer. Its logger shows each step:
discovery, reserve, escrow open and settle.
