# Running ZeroSignal on your own machine

This guide runs every piece of ZeroSignal yourself on a local chain, one terminal per piece, the way
an operator and a user would on a public network: a chain, the operator dashboard to register a
node, the node, a payer, and a chat client. Nothing involves real money. On Solana each step needs
as little configuration as a public network does; on Algorand the escrow app id is the one value
you pass around. The Solana rail comes first; the Algorand rail is below and has the same shape.

The checkouts are siblings of this one: `contracts/` (`TxnLab/zerosignal-contracts`, whose
`solana/` and `algorand/` hold the two contracts), `ui/`, `node/`, `proxy/` and `tui/`, plus
`client/` for the Algorand payer.

## Solana

### Words you will meet

- **Validator**: the program that runs a Solana chain. `solana-test-validator` runs a private one
  on `127.0.0.1:8899` that only this machine uses.
- **Program**: Solana's word for a smart contract. ZeroSignal's is `zs_escrow`; it has the same
  address on every cluster (localnet, devnet), so the address alone does not say which chain you
  are on.
- **Config account**: the program's settings (the USDC mint, the fee, the stakes and the admin),
  written by the deploy; the admin can change the fee and stakes later.
- **Test USDC mint**: on a local chain there is no real USDC, so the deploy creates a token that
  plays its part. Your local mint is your own; it is not devnet's.
- **SOL**: the chain's own coin. Every transaction pays a small fee in SOL, and every account
  holds a little SOL as rent. On a local chain SOL comes free from an airdrop.
- **Token account**: a wallet holds USDC in a separate account per token. The tools create it for
  you the first time USDC arrives.
- **Signing key**: the node's own key. It signs the node's escrow opens and settlements and pays
  their fees, so it needs some SOL. It is a different key from the operator's wallet, which owns
  the operator and node records and their stakes.
- **Rent pool**: a payer's SOL set aside for the escrow tickets it opens; `zs-proxy fund` tops it
  up.

### 1. The chain

```bash
cd contracts/solana
make localnet
```

This builds the program, starts a validator on `127.0.0.1:8899` with it loaded, creates the test
USDC mint and runs the program's setup. The first start makes the local admin, mint and treasury
keys in `target/localnet-keys/`; later starts reuse them, so the mint keeps its address. It prints
the RPC, the program, the mint and the admin. Each start resets the chain, so after a restart you
register and fund again.

Funding any wallet, while the validator runs, is one command:

```bash
make localnet-fund ADDR=<address>                 # 10 SOL and 1000 test USDC
make localnet-fund ADDR=<address> SOL=2 USDC=0    # SOL only
```

`make localnet-stop` stops the validator.

### 2. Register an operator and a node

First make the node's own key, in `node/`, where step 3 loads it from:

```bash
cd node
solana-keygen new --no-bip39-passphrase -o node.json
solana address -k node.json        # the node's signing address
```

Then the dashboard:

```bash
cd ui && pnpm install && pnpm dev
```

Open the page Vite prints, pick **Solana Localnet** in the network switcher, and connect a wallet.
A browser wallet works if it can be pointed at `http://127.0.0.1:8899`; otherwise use the page's
**Dev wallet**, which keeps its key in the browser and exists for localnet only. This wallet is the
operator's owner.

Fund the owner: `make localnet-fund ADDR=<owner address>` in `contracts/solana` (the stakes are
250 test USDC for the operator and 25 for each node after the first). Then register the operator,
and add a node with:

- **Signing address**: the address `solana address -k node.json` printed. Another key works too,
  loaded in step 3 by its phrase or its exported private key. The node loads a recovery phrase as
  that wallet's **first** account (`m/44'/501'/0'/0'`), so the phrase works only for a wallet made
  for the node. An account added to an existing Phantom or Solflare wallet shares that wallet's
  phrase at a later index; load it by its exported private key instead. A `solana-keygen` key loads
  as its file, not as the phrase it printed: `solana-keygen new` derives the key with no path, so
  the printed phrase loads a different address.
- **Base URL**: where the node listens. `zs-node init` writes port 9090, so on this machine that is
  `http://127.0.0.1:9090`. `init` warns when the two disagree.

Note the operator id and node id the page shows.

### 3. The node

```bash
cd node
export ZS_MNEMONIC_URLS=signing=file://$PWD/node.json
# or, for a wallet's key: export OPERATOR_SIGNING_MNEMONIC="the recovery phrase or private key"
go run . init --network solana-localnet --config localnet.yaml
```

Set one of the two, not both: a `ZS_MNEMONIC_URLS` entry that can't be read stops every key from
loading. The signing key may come from any `*_MNEMONIC` variable or from `ZS_MNEMONIC_URLS`, which
also takes cloud secrets, as on Algorand. Either may hold a recovery phrase (a wallet's first
account), a `solana-keygen` keypair file's contents, or an exported base58 private key. When the key
loads but is not the node's, the node refuses to start with `signing address X not loaded (loaded:
[Y])`, naming the address it did load.

`init` asks for the operator and node ids, finds the models your LLM backend serves (LM Studio,
Ollama, vLLM, an OpenAI key, …), prices them and writes `localnet.yaml`, leaving any `config.yaml`
of yours alone. Its chain check reads the program and your node's record, and says when the
signing key is short of SOL. It ends with what to export before the node starts: for a generic
OpenAI-compatible backend that includes `NODE_LLM_OPENAI_API_KEY`, which any placeholder
satisfies when the backend takes no key. Every command that reads the config needs it, so export
it first.

Give the signing key SOL for its fees, then run the node:

```bash
export NODE_LLM_OPENAI_API_KEY=placeholder         # or your backend's key, if init named it
go run . fund-signer --airdrop --config localnet.yaml
go run . --config localnet.yaml
```

### 4. A payer: zs-proxy

A second proxy beside any you already run, with its own wallet and state:

```bash
cd proxy
export ZEROSIGNAL_HOME=~/zs-local
export PROXY_CONFIG=                                # no config file: the network's defaults
go run . wallet new --network solana-localnet       # prints the payer's address
(cd ../contracts/solana && make localnet-fund ADDR=<payer address>)
go run . fund --network solana-localnet             # opens the USDC account and the rent pool
go run . proxy start --network solana-localnet --port 9377
```

The empty `PROXY_CONFIG` matters in a proxy checkout: with no config in `ZEROSIGNAL_HOME`, the
proxy otherwise reads a `config.yaml` in the current directory, which may be your own.

No privacy or private-host setting is needed. On the localnet preset at a loopback endpoint the
payer sends straight to the node, since there is no second operator to relay through, and may
reach a node at a private address such as `127.0.0.1`. Before relying on that it checks the chain
is not devnet, testnet or mainnet behind a tunnel. On any other network both stay off unless you
turn them on. `ZEROSIGNAL_HOME` keeps this wallet, its journals and its logs apart from your own
proxy's, and the OS service and `connect` leave your own setup alone while it is set. A release
build keeps the wallet in the OS keychain, as a separate item from your own; a build from source
keeps it in an encrypted file in that directory and asks for a passphrase.

### 5. Chat

```bash
cd tui
go run . -host http://localhost:9377/v1                    # through the proxy
ZEROSIGNAL_HOME=~/zs-local go run . -direct -network solana-localnet   # the SDK in the TUI, no proxy
```

`-direct` pays from the same wallet as the proxy in step 4 when given the same `ZEROSIGNAL_HOME`.

## Algorand

The same five pieces, on AlgoKit's localnet.

1. **The chain.** `algokit localnet reset`, then deploy the escrow contract, which mints a local
   USDC asset and prints the escrow app id (a fresh reset gives the same app id each time):

   ```bash
   cd contracts/algorand/contracts/bootstrap
   pnpm install --ignore-workspace          # once; it has its own lockfile
   pnpm run bootstrap --network localnet
   ```

   The KMD default wallet holds the localnet ALGO and the bootstrap's USDC. Fund each wallet below
   from it, with `algokit goal clerk send` for ALGO and, once the wallet has opted in to the USDC
   asset, `algokit goal asset send` for USDC.
2. **Register.** In `ui/`, pick **Localnet** and register the operator and node as on testnet. The
   operator's owner needs ALGO, the USDC opt-in and 250 USDC for the stake.
3. **The node.** In `node/`, put the node's signing key (a 25-word Algorand or 24-word phrase) in
   `OPERATOR_SIGNING_MNEMONIC` and send its address ALGO for fees; `fund-signer` is Solana's only.
   Then `go run . init --network localnet --config localnet.yaml`, giving the app id when it asks,
   and run it as on Solana.
4. **A payer.** The chat app (`client/`) creates an account with a passkey; it needs
   `VITE_ALGOD_NETWORK=localnet`, `VITE_ZS_ESCROW_APP_ID=<app id>`, `VITE_ZS_ALLOW_LOCALHOST=1` and
   `VITE_ZS_PRIVACY=0` in `.env.local`. Fund that account with ALGO, and with USDC once it has
   opted in. Then sign a proxy in to it and start it:

   ```bash
   cd proxy
   export ZEROSIGNAL_HOME=~/zs-local-algorand PROXY_CONFIG= PROXY_ZS_ESCROW_APP_ID=<app id>
   go run . wallet login --network localnet --client-url http://localhost:3000
   go run . proxy start --network localnet --port 9377
   ```

   Localnet has no preset app id, so the proxy refuses to start without `PROXY_ZS_ESCROW_APP_ID`
   (or `zs.escrow_app_id` in a config).
5. **Chat.** `tui -host http://localhost:9377/v1` through the proxy, or
   `ZEROSIGNAL_HOME=~/zs-local-algorand tui -direct -network localnet -app-id <app id>`.
